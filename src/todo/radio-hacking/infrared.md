# Infracrveno

{{#include ../../banners/hacktricks-training.md}}

## Kako infracrveni port funkcioniše <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infracrvena svetlost je nevidljiva ljudima**. IR talasna dužina iznosi od **0,7 do 1000 mikrona**. Kućni daljinski upravljači koriste IR signal za prenos podataka i rade u opsegu talasnih dužina od 0,75..1,4 mikrona. Mikrokontroler u daljinskom upravljaču omogućava da infracrvena LED dioda treperi određenom frekvencijom, pretvarajući digitalni signal u IR signal.

Za prijem IR signala koristi se **foto-prijemnik**. On **pretvara IR svetlost u naponske impulse**, koji su već **digitalni signali**. Obično se unutar prijemnika nalazi **filter za ambijentalno svetlo**, koji propušta **samo željenu talasnu dužinu** i uklanja šum.<sup>[[1]](#references)</sup>

### Različiti IR protokoli <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protokoli se razlikuju prema 3 faktora:<sup>[[1]](#references)</sup>

- kodiranje bitova
- struktura podataka
- noseća frekvencija — često u opsegu 36..38 kHz

#### Načini kodiranja bitova <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bitovi se kodiraju modulacijom trajanja pauze između impulsa. Širina samog impulsa je konstantna.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bitovi se kodiraju modulacijom širine impulsa. Širina pauze nakon niza impulsa je konstantna.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Poznato je i kao Manchester encoding. Logička vrednost se određuje polaritetom prelaza između niza impulsa i pauze. „Pauza ka nizu impulsa“ označava logičku „0“, a „niz impulsa ka pauzi“ označava logičku „1“.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombinacija prethodnih načina i druge egzotične metode**

> [!TIP]
> Postoje IR protokoli koji **pokušavaju da postanu univerzalni** za više tipova uređaja. Najpoznatiji su RC5 i NEC. Nažalost, **najpoznatiji ne znači i najčešći**. U svom okruženju susreo sam samo dva NEC daljinska upravljača i nijedan RC5.
>
> Proizvođači vole da koriste sopstvene jedinstvene IR protokole, čak i unutar istog asortimana uređaja (na primer, TV box uređaja). Zbog toga daljinski upravljači različitih kompanija, a ponekad i različitih modela iste kompanije, ne mogu da rade sa drugim uređajima istog tipa.

### Istraživanje IR signala

Najpouzdaniji način da se vidi kako IR signal daljinskog upravljača izgleda jeste korišćenje osciloskopa. On ne demoduliše niti invertuje primljeni signal, već ga samo prikazuje „takvog kakav jeste“. Ovo je korisno za testiranje i debugging. Prikazaću očekivani signal na primeru NEC IR protokola.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Obično se na početku kodiranog paketa nalazi preambula. Ona prijemniku omogućava da odredi nivo pojačanja i pozadinski signal. Postoje i protokoli bez preambule, na primer Sharp.

Zatim se prenose podaci. Struktura, preambula i način kodiranja bitova određeni su konkretnim protokolom.

**NEC IR protokol** sadrži kratku komandu i repeat code, koji se šalje dok je dugme pritisnuto. I komanda i repeat code imaju istu preambulu na početku.

NEC **komanda**, pored preambule, sadrži bajt adrese i bajt broja komande, na osnovu kojih uređaj razume šta treba da izvrši. Bajtovi adrese i broja komande duplirani su inverznim vrednostima radi provere integriteta prenosa. Na kraju komande nalazi se dodatni stop bit.

**Repeat code** nakon preambule ima „1“, koja predstavlja stop bit.

Za **logičke vrednosti „0“ i „1“**, NEC koristi Pulse Distance Encoding: najpre se prenosi niz impulsa, nakon čega sledi pauza čija dužina određuje vrednost bita.

### Klima-uređaji

Za razliku od drugih daljinskih upravljača, **klima-uređaji ne prenose samo kod pritisnutog dugmeta**. Oni takođe **prenose sve informacije** prilikom pritiska na dugme kako bi se obezbedilo da su **klima-uređaj i daljinski upravljač sinhronizovani**.\
Time se sprečava da uređaj podešen na 20 ºC pomoću jednog daljinskog upravljača bude povećan na 21 ºC, a da zatim, kada se upotrebi drugi daljinski upravljač koji i dalje ima podešenu temperaturu na 20 ºC, temperatura ponovo bude „povećana“ na 21 ºC (umesto na 22 ºC, jer drugi daljinski upravljač smatra da je temperatura 21 ºC).<sup>[[1]](#references)</sup>

---

## Napadi i Offensive Research <a href="#attacks" id="attacks"></a>

Možete napasti infracrvene uređaje pomoću Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Preuzimanje Smart-TV / Set-top Box uređaja (EvilScreen)

Nedavna akademska istraživanja (EvilScreen, 2022) pokazala su da **multi-channel daljinski upravljači koji kombinuju infracrvenu vezu sa Bluetooth ili Wi-Fi vezom mogu biti zloupotrebljeni za potpuno preuzimanje modernih Smart-TV uređaja**. Napad povezuje IR service kodove sa visokim privilegijama sa autentifikovanim Bluetooth paketima, zaobilazeći izolaciju kanala i omogućavajući proizvoljno pokretanje aplikacija, aktiviranje mikrofona ili factory reset bez fizičkog pristupa. Potvrđeno je da je osam rasprostranjenih televizora različitih proizvođača — uključujući Samsung model koji tvrdi da je usklađen sa standardom ISO/IEC 27001 — ranjivo. Ublažavanje rizika zahteva firmware ispravke proizvođača ili potpuno onemogućavanje nekorišćenih IR prijemnika.<sup>[[2]](#references)</sup>

### Exfiltration podataka iz air-gapped sistema putem IR LED dioda (aIR-Jumper family)

Sigurnosne kamere često sadrže **IR LED diode za noćni vid**. Prototip aIR-Jumper pokazao je da malware koji kontroliše te diode može **exfiltrirati tajne kroz prozore** ka spoljašnjoj kameri brzinom do **20 bit/s po nadzornoj kameri** na udaljenostima od nekoliko desetina metara. U suprotnom smeru, istraživači su demonstrirali infiltration brzinom većom od **100 bit/s** na udaljenostima od nekoliko stotina metara do nekoliko kilometara.<sup>[[3]](#references)</sup> Pošto je svetlost izvan vidljivog spektra, operateri je možda neće primetiti. Mere zaštite uključuju:

* Fizički zaštitite ili uklonite IR LED diode u osetljivim područjima
* Nadgledajte duty-cycle LED dioda kamere i integritet firmware-a
* Postavite IR-cut filtere na prozore i nadzorne kamere

Napadač takođe može koristiti snažne IR projektore za **infiltraciju** komandi u mrežu, treperenjem podataka ka nezaštićenim kamerama.

### Brute-Force na velikim udaljenostima i prošireni protokoli sa Flipper Zero 1.0

Firmware 1.0 (septembar 2024) proširio je biblioteku univerzalnih daljinskih upravljača i dodao dinamičko učitavanje infrared asset fajlova sa microSD kartice.<sup>[[4]](#references)</sup> Njegove funkcije za učenje i univerzalni daljinski upravljač mogu ponavljati ili isprobavati poznate komande protiv obližnjih televizora i klima-uređaja. Domet u velikoj meri zavisi od emitera, optike, ambijentalnog svetla i prijemnika; eksterni IR hardware ga može proširiti, ali ne treba pretpostavljati fiksnu udaljenost.

---

## Alati i praktični primeri <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – prenosivi transceiver sa režimima za učenje, replay i dictionary-bruteforce (pogledajte iznad).
* **Arduino / ESP32** + IR LED / TSOP38xx prijemnik – jeftin DIY analizator/transmiter. Kombinujte ga sa bibliotekom `Arduino-IRremote` (v4.x podržava više od 40 protokola).
* **Logic analysers** (Saleae/FX2) – snimaju sirova vremena kada je protokol nepoznat.
* **Smartphone uređaji sa IR-blasterom** (npr. Xiaomi) – brzi field test, ali sa ograničenim dometom.

### Software

* **`Arduino-IRremote`** – aktivno održavana C++ biblioteka:<sup>[[5]](#references)</sup>
```cpp
#include <IRremote.hpp>
void setup(){ IrSender.begin(3); }
void loop(){
IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI dekoderi koji uvoze sirove snimke, automatski identifikuju protokol i generišu Pronto/Arduino kod.
* **LIRC / ir-keytable (Linux)** – primaju i ubacuju IR iz komandne linije:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Mere zaštite <a href="#defense" id="defense"></a>

* Onemogućite ili prekrijte IR prijemnike na uređajima postavljenim na javnim mestima kada nisu potrebni.
* Primenite *pairing* ili kriptografske provere između Smart-TV uređaja i daljinskih upravljača; izolujte privilegovane „service“ kodove.
* Postavite IR-cut filtere ili detektore kontinuiranog talasa oko poverljivih područja kako biste prekinuli optičke covert channels.
* Nadgledajte integritet firmware-a kamera/IoT uređaja koji izlažu kontrolabilne IR LED diode.

## References

- [1] [Blog tekst o infracrvenoj vezi Flipper Zero](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen napad: preuzimanje Smart-TV uređaja putem oponašanja multi-channel daljinskog upravljača (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: covert exfiltration/infiltration iz air-gap sistema putem sigurnosnih kamera i infracrvene veze (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero blog - Firmware 1.0 je objavljen](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - upotreba i dokumentacija protokola](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
