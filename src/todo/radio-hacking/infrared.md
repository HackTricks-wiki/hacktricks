# Infrarooi

{{#include ../../banners/hacktricks-training.md}}

## Hoe die Infrarooi Werk <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrarooi lig is onsigbaar vir mense**. IR golflengte is van **0.7 tot 1000 mikron**. Huishoudelike afstandsbedienings gebruik 'n IR sein vir datatransmissie en werk in die golflengte reeks van 0.75..1.4 mikron. 'n Mikrocontroller in die afstandsbediening laat 'n infrarooi LED flits met 'n spesifieke frekwensie, wat die digitale sein in 'n IR sein omskakel.

Om IR seine te ontvang, word 'n **fotoreceiver** gebruik. Dit **omskakel IR lig in spanning pulsies**, wat reeds **digitale seine** is. Gewoonlik is daar 'n **donker ligfilter binne die ontvanger**, wat **slegs die gewenste golflengte deurlaat** en geraas uitsny.

### Verskeidenheid van IR Protokolle <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protokolle verskil in 3 faktore:

- bit kodering
- datastruktuur
- draerfrekwensie — dikwels in die reeks 36..38 kHz

#### Manier van Bit Kodering <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulsafstand Kodering**

Bits word gekodeer deur die duur van die spasie tussen pulsies te moduler. Die breedte van die puls self is konstant.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulsbreedte Kodering**

Bits word gekodeer deur die pulsbreedte te moduler. Die breedte van die spasie na die pulsuitbarsting is konstant.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Fase Kodering**

Dit is ook bekend as Manchester kodering. Die logiese waarde word gedefinieer deur die polariteit van die oorgang tussen pulsuitbarsting en spasie. "Spasie na pulsuitbarsting" dui logika "0" aan, "pulsuitbarsting na spasie" dui logika "1" aan.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombinasie van vorige en ander eksotiese metodes**

> [!TIP]
> Daar is IR protokolle wat **probeer om universeel te word** vir verskeie tipes toestelle. Die bekendste is RC5 en NEC. Ongelukkig beteken die bekendste **nie die mees algemene** nie. In my omgewing het ek net twee NEC afstandsbedienings ontmoet en geen RC5 nie.
>
> Fabrikante hou daarvan om hul eie unieke IR protokolle te gebruik, selfs binne dieselfde reeks toestelle (byvoorbeeld, TV-doosies). Daarom kan afstandsbedienings van verskillende maatskappye en soms van verskillende modelle van dieselfde maatskappy, nie met ander toestelle van dieselfde tipe werk nie.

### Verkenning van 'n IR sein

Die mees betroubare manier om te sien hoe die afstandsbediening se IR sein lyk, is om 'n oscilloskoop te gebruik. Dit demoduleer of keer nie die ontvangde sein om nie, dit word net "soos dit is" vertoon. Dit is nuttig vir toetsing en foutopsporing. Ek sal die verwagte sein op die voorbeeld van die NEC IR protokol wys.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Gewoonlik is daar 'n preamble aan die begin van 'n gekodeerde pakket. Dit laat die ontvanger toe om die vlak van versterking en agtergrond te bepaal. Daar is ook protokolle sonder preamble, byvoorbeeld, Sharp.

Dan word data oorgedra. Die struktuur, preamble, en bit kodering metode word deur die spesifieke protokol bepaal.

**NEC IR protokol** bevat 'n kort opdrag en 'n herhalingskode, wat gestuur word terwyl die knoppie ingedruk word. Beide die opdrag en die herhalingskode het dieselfde preamble aan die begin.

NEC **opdrag**, benewens die preamble, bestaan uit 'n adresbyte en 'n opdrag-nommer byte, waardeur die toestel verstaan wat gedoen moet word. Adres en opdrag-nommer bytes word gedupliseer met omgekeerde waardes, om die integriteit van die oordrag te kontroleer. Daar is 'n bykomende stopbit aan die einde van die opdrag.

Die **herhalingskode** het 'n "1" na die preamble, wat 'n stopbit is.

Vir **logika "0" en "1"** gebruik NEC Pulsafstand Kodering: eerstens word 'n pulsuitbarsting oorgedra waarna daar 'n pouse is, waarvan die lengte die waarde van die bit bepaal.

### Lugversorgers

In teenstelling met ander afstandsbedienings, **stuur lugversorgers nie net die kode van die ingedrukte knoppie nie**. Hulle **stuur ook al die inligting** wanneer 'n knoppie ingedruk word om te verseker dat die **lugversorgingsmasjien en die afstandsbediening gesinchroniseer is**.\
Dit sal verhoed dat 'n masjien wat op 20ºC gestel is, verhoog word na 21ºC met een afstandsbediening, en dan wanneer 'n ander afstandsbediening, wat steeds die temperatuur as 20ºC het, gebruik word om die temperatuur verder te verhoog, dit "verhoog" dit na 21ºC (en nie na 22ºC nie, dink dit is op 21ºC).

---

## Aanvalle & Aanvallende Navorsing <a href="#attacks" id="attacks"></a>

Jy kan Infrarooi aanval met Flipper Zero:

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Slim-TV / Set-top Box Oorneming (EvilScreen)

Onlangse akademiese werk (EvilScreen, 2022) het getoon dat **multikanal afstandsbedienings wat Infrarooi met Bluetooth of Wi-Fi kombineer, misbruik kan word om moderne slim-TV's volledig oor te neem**. Die aanvalkettings kombineer hoëprivilege IR dienskode met geverifieerde Bluetooth-pakkette, wat kanaal-isolasie omseil en willekeurige app-lanseer, mikrofoonaktivering, of fabrieksherstel sonder fisiese toegang toelaat. Agt hoofstroom-TV's van verskillende verskaffers — insluitend 'n Samsung-model wat ISO/IEC 27001-nakoming beweer — is bevestig as kwesbaar. Mitigering vereis verskaffer firmware regstellings of die heeltemal deaktiveer van ongebruikte IR ontvangers.

### Lug-Gap Data Uitsifting via IR LED's (aIR-Jumper familie)

Sekuriteitskamara's, routers of selfs kwaadwillige USB-sticks sluit dikwels **nagvisie IR LED's** in. Navorsing toon dat malware hierdie LED's kan moduler (<10–20 kbit/s met eenvoudige OOK) om **geheime inligting deur mure en vensters uit te filter** na 'n eksterne kamera wat tien meter weg geplaas is. Omdat die lig buite die sigbare spektrum is, merk operateurs selde dit op. Teenmaatreëls:

* Fisies beskerm of verwyder IR LED's in sensitiewe areas
* Monitor kamera LED pligsyklus en firmware integriteit
* Plaas IR-snyfilters op vensters en toesig kameras

'n Aanvaller kan ook sterk IR projekteerders gebruik om **opdragte** in die netwerk in te voer deur data terug te flits na onveilige kameras.

### Langafstand Brute-Force & Uitgebreide Protokolle met Flipper Zero 1.0

Firmware 1.0 (September 2024) het **tientalle ekstra IR protokolle en opsionele eksterne versterkermodules** bygevoeg. Gecombineer met die universele-afstandsbediening brute-force modus, kan 'n Flipper die meeste openbare TV's/AC's tot 30 m van 'n hoëkragdiode deaktiveer of herkonfigureer.

---

## Gereedskap & Praktiese Voorbeelde <a href="#tooling" id="tooling"></a>

### Hardeware

* **Flipper Zero** – draagbare transceiver met leer-, herhaal- en woordeboek-brute-force modi (sien hierbo).
* **Arduino / ESP32** + IR LED / TSOP38xx ontvanger – goedkoop DIY ontleder/ transmitter. Kombineer met die `Arduino-IRremote` biblioteek (v4.x ondersteun >40 protokolle).
* **Logika ontleders** (Saleae/FX2) – vang rou tyds wanneer protokol onbekend is.
* **Slimfone met IR-blaster** (bv. Xiaomi) – vinnige veldtoets maar beperkte reeks.

### Sagteware

* **`Arduino-IRremote`** – aktief onderhoude C++ biblioteek:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Krag
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI dekoders wat rou vangste invoer en outomaties protokol identifiseer + Pronto/Arduino kode genereer.
* **LIRC / ir-keytable (Linux)** – ontvang en inspuit IR vanaf die opdraglyn:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump gedecodeerde scankodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Verdedigingsmaatreëls <a href="#defense" id="defense"></a>

* Deaktiveer of bedek IR ontvangers op toestelle wat in openbare ruimtes ontplooi word wanneer dit nie benodig word nie.
* Handhaaf *pareer* of kriptografiese kontroles tussen slim-TV's en afstandsbedienings; isoleer bevoorregte “diens” kodes.
* Plaas IR-snyfilters of deurlopende golfdetektore rondom geklassifiseerde areas om optiese verborge kanale te breek.
* Monitor firmware integriteit van kameras/IoT toestelle wat kontroleerbare IR LED's blootstel.

## Verwysings

- [Flipper Zero Infrarooi blogpos](https://blog.flipperzero.one/infrared/)
- EvilScreen: Slim TV oorneming via afstandsbediening nabootsing (arXiv 2210.03014)

{{#include ../../banners/hacktricks-training.md}}
