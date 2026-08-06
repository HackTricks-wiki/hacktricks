# Infrarooi

{{#include ../../banners/hacktricks-training.md}}

## Hoe die infrarooi werk <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrarooi lig is onsigbaar vir mense**. Die IR-golflengte is van **0.7 tot 1000 mikron**. Huishoudelike afstandbeheerders gebruik 'n IR-sein vir data-oordrag en werk in die golflengtereeks van 0.75..1.4 mikron. 'n Mikrobeheerder in die afstandbeheerder laat 'n infrarooi-LED teen 'n spesifieke frekwensie flikker, wat die digitale sein in 'n IR-sein omskakel.

'n **Fotontvanger** word gebruik om IR-seine te ontvang. Dit **skakel IR-lig om in spanningspulse**, wat reeds **digitale seine** is. Gewoonlik is daar 'n **donkerligfilter binne die ontvanger**, wat **slegs die verlangde golflengte deurlaat** en geraas uitsny.<sup>[[1]](#references)</sup>

### Verskeidenheid IR-protokolle <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR-protokolle verskil in 3 faktore:<sup>[[1]](#references)</sup>

- bis-enkodering
- datastruktuur
- drafrekwensie — dikwels in die reeks 36..38 kHz

#### Maniere van bis-enkodering <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bisse word geënkodeer deur die duur van die spasie tussen pulse te moduleer. Die wydte van die puls self is konstant.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bisse word deur die modulasie van die pulswydte geënkodeer. Die wydte van die spasie ná die puls-burst is konstant.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Dit staan ook as Manchester encoding bekend. Die logiese waarde word deur die polariteit van die oorgang tussen die puls-burst en spasie bepaal. "Spasie na puls-burst" dui logika "0" aan, en "puls-burst na spasie" dui logika "1" aan.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombinasie van die voriges en ander eksotiese metodes**

> [!TIP]
> Daar is IR-protokolle wat **universeel vir verskeie tipes toestelle probeer word**. Die bekendste is RC5 en NEC. Ongelukkig beteken die **bekendste nie die algemeenste nie**. In my omgewing het ek slegs twee NEC-afstandbeheerders en geen RC5-eenhede teëgekom nie.
>
> Vervaardigers gebruik graag hul eie unieke IR-protokolle, selfs binne dieselfde reeks toestelle (byvoorbeeld TV-bokse). Daarom kan afstandbeheerders van verskillende maatskappye, en soms van verskillende modelle van dieselfde maatskappy, nie met ander toestelle van dieselfde tipe werk nie.

### Verkenning van 'n IR-sein

Die betroubaarste manier om te sien hoe die IR-sein van die afstandbeheerder lyk, is om 'n ossilloskoop te gebruik. Dit demoduleer of inverteer nie die ontvangde sein nie; dit word bloot "soos dit is" vertoon. Dit is nuttig vir toetsing en debugging. Ek sal die verwagte sein aan die hand van die NEC IR-protokol wys.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Gewoonlik is daar aan die begin van 'n geënkodeerde pakkie 'n aanhef. Dit stel die ontvanger in staat om die vlak van versterking en agtergrond te bepaal. Daar is ook protokolle sonder 'n aanhef, byvoorbeeld Sharp.

Daarna word data oorgedra. Die struktuur, aanhef en bis-enkoderingsmetode word deur die spesifieke protokol bepaal.

**Die NEC IR-protokol** bevat 'n kort opdrag en 'n herhalingskode, wat gestuur word terwyl die knoppie gedruk word. Beide die opdrag en die herhalingskode het dieselfde aanhef aan die begin.

Die NEC-**opdrag** bestaan, benewens die aanhef, uit 'n adresgreep en 'n opdrag-nommer-greep, waarvolgens die toestel verstaan wat uitgevoer moet word. Adres- en opdrag-nommer-grepe word met inverse waardes gedupliseer om die integriteit van die oordrag te kontroleer. Daar is 'n bykomende stopbis aan die einde van die opdrag.

Die **herhalingskode** het 'n "1" ná die aanhef, wat 'n stopbis is.

Vir **logika "0" en "1"** gebruik NEC Pulse Distance Encoding: eerstens word 'n puls-burst gestuur, waarna daar 'n pouse is; die lengte daarvan bepaal die waarde van die bis.

### Lugversorgers

Anders as ander afstandbeheerders, **stuur lugversorgers nie net die kode van die gedrukte knoppie nie**. Hulle **stuur ook al die inligting** wanneer 'n knoppie gedruk word om te verseker dat die **lugversorgde toestel en die afstandbeheerder gesinchroniseer is**.\
Dit voorkom dat 'n toestel wat op 20ºC gestel is, met een afstandbeheerder na 21ºC verhoog word, en dat die temperatuur daarna met 'n ander afstandbeheerder, wat steeds die temperatuur as 20ºC het, verder verhoog word en dit na 21ºC "verhoog" (in plaas van na 22ºC, omdat dit dink die temperatuur is reeds 21ºC).<sup>[[1]](#references)</sup>

---

## Aanvalle & offensiewe navorsing <a href="#attacks" id="attacks"></a>

Jy kan Infrarooi met Flipper Zero aanval:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Oorname van Smart-TV / Set-top Box (EvilScreen)

Onlangse akademiese werk (EvilScreen, 2022) het gedemonstreer dat **multi-kanaal-afstandbeheerders wat Infrarooi met Bluetooth of Wi-Fi kombineer, misbruik kan word om moderne smart-TV's volledig te kaap**. Die aanval kombineer IR-dienskodes met hoë voorregte met geverifieerde Bluetooth-pakkette, omseil kanaalisolasie en maak arbitrêre programlanserings, mikrofoonaktivering of 'n fabriekterugstelling sonder fisiese toegang moontlik. Daar is bevestig dat agt hoofstroom-TV's van verskillende verskaffers — insluitend 'n Samsung-model wat ISO/IEC 27001-nakoming beweer — kwesbaar is. Versagting vereis firmware-regstellings van die verskaffer of die volledige deaktivering van ongebruikte IR-ontvangers.<sup>[[2]](#references)</sup>

### Lug-gaping-data-uitlekking via IR-LED's (aIR-Jumper-familie)

Sekuriteitskameras, routers en selfs kwaadwillige USB-stokkies bevat dikwels **infrarooi-LED's vir nagsig**. Navorsing toon dat malware hierdie LED's kan moduleer (<10–20 kbit/s met eenvoudige OOK) om **geheime deur mure en vensters uit te lek** na 'n eksterne kamera wat tientalle meter verder geplaas is.<sup>[[3]](#references)</sup> Omdat die lig buite die sigbare spektrum is, merk operateurs dit selde op. Teenmaatreëls:

* Fisies beskerm of verwyder IR-LED's in sensitiewe gebiede
* Monitor die LED-dienssiklus en firmware-integriteit van kameras
* Ontplooi IR-snyfilters op vensters en toesigkameras

'n Aanvaller kan ook sterk IR-projektors gebruik om opdragte in die netwerk te **infiltreer** deur data terug te flits na onseker kameras.

### Brute-force oor lang afstande & uitgebreide protokolle met Flipper Zero 1.0

Firmware 1.0 (September 2024) het **dosyne ekstra IR-protokolle en opsionele eksterne versterkermodules** bygevoeg. Gekombineer met die universele-afstandbeheerder-brute-force-modus kan 'n Flipper die meeste openbare TV's/AC's van tot 30 m af deaktiveer of herkonfigureer deur 'n hoëkragdiode te gebruik.

---

## Tooling & praktiese voorbeelde <a href="#tooling" id="tooling"></a>

### Hardeware

* **Flipper Zero** – draagbare transceiver met leer-, replay- en dictionary-bruteforce-modusse (sien hierbo).
* **Arduino / ESP32** + IR-LED / TSOP38xx-ontvanger – goedkoop DIY-ontleder/-sender. Kombineer dit met die `Arduino-IRremote`-library (v4.x ondersteun >40 protokolle).
* **Logic analysers** (Saleae/FX2) – neem rou tydsberekeninge vas wanneer die protokol onbekend is.
* **Slimfone met IR-blaster** (bv. Xiaomi) – vinnige veldtoets, maar met beperkte reikwydte.

### Sagteware

* **`Arduino-IRremote`** – aktief onderhoude C++-library:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI-dekodeerders wat rou opnames invoer, die protokol outomaties identifiseer en Pronto/Arduino-kode genereer.
* **LIRC / ir-keytable (Linux)** – ontvang en injecteer IR vanaf die command line:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensiewe maatreëls <a href="#defense" id="defense"></a>

* Deaktiveer of bedek IR-ontvangers op toestelle wat in openbare ruimtes ontplooi is wanneer dit nie vereis word nie.
* Dwing *pairing* of kriptografiese kontroles tussen smart-TV's en afstandbeheerders af; isoleer bevoorregte “diens”-kodes.
* Ontplooi IR-snyfilters of aaneenlopende-golf-detektors rondom geklassifiseerde gebiede om optiese geheime kanale te verbreek.
* Monitor die firmware-integriteit van kameras/IoT-toestelle wat beheerbare IR-LED's blootstel.

## Verwysings

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)

{{#include ../../banners/hacktricks-training.md}}
