# Infrarooi

{{#include ../../banners/hacktricks-training.md}}

## Hoe die Infrarooi Werk <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrarooi lig is onsigbaar vir mense**. IR-golflengte strek van **0.7 tot 1000 mikron**. Huishoudelike afstandbeheerders gebruik ’n IR-sein vir data-oordrag en werk binne die golflengtereeks van 0.75..1.4 mikron. ’n Mikrobeheerder in die afstandbeheerder laat ’n infrarooi-LED teen ’n spesifieke frekwensie flikker, wat die digitale sein in ’n IR-sein omskakel.

Om IR-seine te ontvang, word ’n **fotontvanger** gebruik. Dit **skakel IR-lig om in spanningspulse**, wat reeds **digitale seine** is. Gewoonlik is daar ’n **donkerligfilter binne die ontvanger**, wat **slegs die gewenste golflengte deurlaat** en geraas uitsny.<sup>[[1]](#references)</sup>

### Verskeidenheid IR-protokolle <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR-protokolle verskil volgens 3 faktore:<sup>[[1]](#references)</sup>

- bisenkodering
- datastruktuur
- draagdraerfrekwensie — dikwels in die reeks 36..38 kHz

#### Maniere van bisenkodering <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bisse word geënkodeer deur die duur van die spasie tussen pulse te moduleer. Die breedte van die puls self is konstant.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bisse word geënkodeer deur die pulsbreedte te moduleer. Die breedte van die spasie ná die pulstrein is konstant.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Dit staan ook as Manchester encoding bekend. Die logiese waarde word deur die polariteit van die oorgang tussen die pulstrein en spasie bepaal. "Spasie na pulstrein" dui logika "0" aan, en "pulstrein na spasie" dui logika "1" aan.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombinasie van voriges en ander eksotiese metodes**

> [!TIP]
> Daar is IR-protokolle wat **universeel probeer word** vir verskeie tipes toestelle. Die bekendstes is RC5 en NEC. Ongelukkig beteken die **bekendste nie die algemeenste nie**. In my omgewing het ek slegs twee NEC-afstandbeheerders en geen RC5-eenhede teëgekom nie.
>
> Vervaardigers gebruik graag hul eie unieke IR-protokolle, selfs binne dieselfde reeks toestelle (byvoorbeeld TV-bokse). Daarom kan afstandbeheerders van verskillende maatskappye, en soms van verskillende modelle van dieselfde maatskappy, nie met ander toestelle van dieselfde tipe werk nie.

### Ondersoek van ’n IR-sein

Die betroubaarste manier om te sien hoe die IR-sein van die afstandbeheerder lyk, is om ’n ossilloskoop te gebruik. Dit demoduleer of inverteer nie die ontvangde sein nie; dit vertoon dit bloot "soos dit is". Dit is nuttig vir toetsing en ontfouting. Ek sal die verwagte sein aan die hand van die NEC IR-protokol wys.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Gewoonlik is daar ’n aanhef aan die begin van ’n geënkodeerde pakkie. Dit stel die ontvanger in staat om die vlak van versterking en die agtergrond te bepaal. Daar is ook protokolle sonder ’n aanhef, byvoorbeeld Sharp.

Daarna word data oorgedra. Die struktuur, aanhef en bisenkoderingsmetode word deur die spesifieke protokol bepaal.

**NEC IR-protokol** bevat ’n kort command en ’n repeat code, wat gestuur word terwyl die knoppie gedruk word. Beide die command en die repeat code het dieselfde aanhef aan die begin.

Die NEC **command** bestaan, benewens die aanhef, uit ’n adresgreep en ’n command-nommergreep, waarmee die toestel verstaan wat uitgevoer moet word. Adres- en command-nommergrepe word met inverse waardes gedupliseer om die integriteit van die oordrag te kontroleer. Daar is ’n bykomende stopbis aan die einde van die command.

Die **repeat code** het ’n "1" ná die aanhef, wat ’n stopbis is.

Vir **logika "0" en "1"** gebruik NEC Pulse Distance Encoding: eerstens word ’n pulstrein gestuur, gevolg deur ’n pouse waarvan die lengte die waarde van die bis bepaal.

### Lugversorgers

Anders as ander afstandbeheerders, **stuur lugversorgers nie slegs die kode van die gedrukte knoppie nie**. Hulle **stuur ook al die inligting** wanneer ’n knoppie gedruk word om te verseker dat die **lugversorgingseenheid en die afstandbeheerder gesinchroniseer is**.\
Dit voorkom dat ’n eenheid wat op 20ºC gestel is, met een afstandbeheerder na 21ºC verhoog word, en dat die temperatuur daarna met ’n ander afstandbeheerder, wat steeds die temperatuur as 20ºC het, verder verhoog word na 21ºC (en nie na 22ºC nie, omdat dit dink die temperatuur is reeds 21ºC).<sup>[[1]](#references)</sup>

---

## Aanvalle & Offensiewe Navorsing <a href="#attacks" id="attacks"></a>

Jy kan Infrarooi met Flipper Zero aanval:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Oorname van Smart-TV / Set-top Box (EvilScreen)

Onlangse akademiese navorsing (EvilScreen, 2022) het getoon dat **multi-kanaal-afstandbeheerders wat Infrarooi met Bluetooth of Wi-Fi kombineer, misbruik kan word om moderne smart-TV’s volledig te kaap**. Die aanvalsketting kombineer IR-dienskodes met hoë voorregte met geverifieerde Bluetooth-pakkies, omseil kanaalisolasie en maak arbitrêre programlanserings, mikrofoonaktivering of ’n fabrieksterugstelling sonder fisiese toegang moontlik. Daar is bevestig dat agt algemene TV’s van verskillende verskaffers — insluitend ’n Samsung-model wat ISO/IEC 27001-nakoming beweer — kwesbaar is. Versagting vereis firmware-herstelwerk deur die verskaffer of die volledige deaktivering van ongebruikte IR-ontvangers.<sup>[[2]](#references)</sup>

### Data-ekfiltrasie vanaf ’n luggeïsoleerde netwerk via IR-LED’s (aIR-Jumper-familie)

Sekuriteitskameras bevat dikwels **infrarooi-LED’s vir nagsig**. Die aIR-Jumper-prototipe het getoon dat malware wat daardie LED’s beheer, **geheime deur vensters na ’n eksterne kamera kan eksfiltreer** teen tot **20 bis/s per toesigkamera** oor tientalle meter. In die omgekeerde rigting het die navorsers infiltrasie teen meer as **100 bis/s** oor afstande van honderde meter tot kilometers gedemonstreer.<sup>[[3]](#references)</sup> Omdat die lig buite die sigbare spektrum is, sal operateurs dit moontlik nie opmerk nie. Teenmaatreëls sluit in:

* Skerm of verwyder IR-LED’s fisies in sensitiewe gebiede
* Monitor die kameraled-dienssiklus en firmware-integriteit
* Ontplooi IR-snyfilters op vensters en toesigkameras

’n Aanvaller kan ook sterk IR-projektors gebruik om opdragte in die netwerk te **infiltreer** deur data terug na onveilige kameras te flits.

### Brute-force oor lang afstande & uitgebreide protokolle met Flipper Zero 1.0

Firmware 1.0 (September 2024) het die universal-remotes-biblioteek uitgebrei en dinamiese laai van infrarooi-bate-lêers vanaf microSD bygevoeg.<sup>[[4]](#references)</sup> Die leer- en universal-remote-funksies kan bekende opdragte teen nabygeleë TV’s en lugversorgers herhaal of probeer. Bereik hang sterk af van die emitter, optika, omgewingslig en ontvanger; eksterne IR-hardeware kan dit uitbrei, maar ’n vaste afstand moet nie aanvaar word nie.

---

## Gereedskap & Praktiese Voorbeelde <a href="#tooling" id="tooling"></a>

### Hardeware

* **Flipper Zero** – draagbare transceiver met leer-, herhaal- en dictionary-bruteforce-modusse (sien hierbo).
* **Arduino / ESP32** + IR-LED / TSOP38xx-ontvanger – goedkoop DIY-ontleder/-sender. Kombineer met die `Arduino-IRremote`-biblioteek (v4.x ondersteun >40 protokolle).
* **Logika-ontleders** (Saleae/FX2) – vang rou tydsberekeninge vas wanneer die protokol onbekend is.
* **Slimfone met IR-blaster** (bv. Xiaomi) – vinnige veldtoets, maar met beperkte bereik.

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
* **IRscrutinizer / AnalysIR** – GUI-dekodeerders wat rou opnames invoer, die protokol outomaties identifiseer en Pronto-/Arduino-kode genereer.
* **LIRC / ir-keytable (Linux)** – ontvang en injecteer IR vanaf die command line:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Verdedigingsmaatreëls <a href="#defense" id="defense"></a>

* Deaktiveer of bedek IR-ontvangers op toestelle wat in openbare ruimtes ontplooi is wanneer dit nie vereis word nie.
* Dwing *pairing* of kriptografiese kontroles tussen smart-TV’s en afstandbeheerders af; isoleer bevoorregte “diens”-kodes.
* Ontplooi IR-snyfilters of aaneenlopende-golf-detektors rondom geklassifiseerde gebiede om optiese geheime kanale te verbreek.
* Monitor die firmware-integriteit van kameras/IoT-toestelle wat beheerbare IR-LED’s blootstel.

## References

- [1] [Flipper Zero Infrarooi-blogplasing](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen-aanval: Smart-TV-kaapping via multikanaal-afstandbeheer-nabootsing (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Bedekte lugruim-ekfiltrasie/-infiltrasie via sekuriteitskameras en infrarooi (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero-blog - Firmware 1.0 vrygestel](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - gebruiks- en protokol-dokumentasie](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
