# Infracrveno

{{#include ../../banners/hacktricks-training.md}}

## Kako infracrveni port funkcioniše <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infracrvena svetlost je nevidljiva ljudima**. IR talasna dužina iznosi od **0.7 do 1000 mikrona**. Kućni daljinski upravljači koriste IR signal za prenos podataka i rade u opsegu talasnih dužina od 0.75..1.4 mikrona. Mikrokontroler u daljinskom upravljaču uključuje i isključuje infracrvenu LED diodu određenom frekvencijom, pretvarajući digitalni signal u IR signal.<sup>[[1]](#references)</sup>

Za prijem IR signala koristi se **fotoprijemnik**. On **pretvara IR svetlost u naponske impulse**, koji su već **digitalni signali**. U prijemniku se obično nalazi **filter za ambijentalnu svetlost**, koji propušta **samo željenu talasnu dužinu** i uklanja šum.

### Raznovrsnost IR protokola <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protokoli se razlikuju u 3 faktora:

- kodiranje bitova
- struktura podataka
- noseća frekvencija — često u opsegu 36..38 kHz

#### Načini kodiranja bitova <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bitovi se kodiraju modulacijom trajanja prostora između impulsa. Širina samog impulsa je konstantna.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bitovi se kodiraju modulacijom širine impulsa. Širina prostora nakon burst-a impulsa je konstantna.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Poznato je i kao Manchester encoding. Logička vrednost se određuje polaritetom prelaza između burst-a impulsa i prostora. "Space to pulse burst" označava logiku "0", a "pulse burst to space" označava logiku "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombinacija prethodnih i drugih egzotičnih metoda**

> [!TIP]
> Postoje IR protokoli koji **pokušavaju da postanu univerzalni** za više vrsta uređaja. Najpoznatiji su RC5 i NEC. Nažalost, to što je nešto **najpoznatije ne znači da je i najčešće**. U svom okruženju sam naišao na samo dva NEC daljinska upravljača i nijedan RC5.
>
> Proizvođači vole da koriste sopstvene jedinstvene IR protokole, čak i unutar istog opsega uređaja (na primer, TV box uređaja). Zato daljinski upravljači različitih kompanija, a ponekad i različitih modela iste kompanije, ne mogu da rade sa drugim uređajima iste vrste.

### Istraživanje IR signala

Najpouzdaniji način da se vidi kako izgleda IR signal daljinskog upravljača jeste korišćenje osciloskopa. On ne demoduliše niti invertuje primljeni signal, već ga samo prikazuje „takvog kakav jeste“. To je korisno za testiranje i debugging. Prikazaću očekivani signal na primeru NEC IR protokola.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Na početku kodiranog paketa obično se nalazi preambula. Ona prijemniku omogućava da odredi nivo pojačanja i pozadinu. Postoje i protokoli bez preambule, na primer Sharp.

Zatim se prenose podaci. Strukturu, preambulu i metod kodiranja bitova određuje konkretni protokol.

**NEC IR protokol** sadrži kratku komandu i repeat code, koji se šalje dok je dugme pritisnuto. I komanda i repeat code na početku imaju istu preambulu.

NEC **command**, pored preambule, sadrži bajt adrese i bajt broja komande, na osnovu kojih uređaj razume šta treba izvršiti. Bajtovi adrese i broja komande dupliraju se inverznim vrednostima radi provere integriteta prenosa. Na kraju komande nalazi se dodatni stop bit.

**Repeat code** nakon preambule ima „1“, koja predstavlja stop bit.

Za **logiku „0“ i „1“** NEC koristi Pulse Distance Encoding: najpre se prenosi burst impulsa, nakon čega sledi pauza čija dužina određuje vrednost bita.

### Klima-uređaji

Za razliku od drugih daljinskih upravljača, **klima-uređaji ne prenose samo kod pritisnutog dugmeta**. Oni takođe **prenose sve informacije** kada se pritisne dugme, kako bi se obezbedilo da **klima-uređaj i daljinski upravljač budu sinhronizovani**.\
Time se sprečava da uređaj podešen na 20ºC jednim daljinskim upravljačem bude podešen na 21ºC, a da ga zatim drugim daljinskim upravljačem, koji i dalje ima temperaturu podešenu na 20ºC, povećamo na 21ºC (umesto na 22ºC, jer „misli“ da je temperatura 21ºC).

---

## Napadi i ofanzivno istraživanje <a href="#attacks" id="attacks"></a>

Infrared možete napasti pomoću Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Preuzimanje Smart-TV / Set-top Box uređaja (EvilScreen)

Nedavni akademski rad (EvilScreen, 2022) pokazao je da **multikanalni daljinski upravljači koji kombinuju Infrared sa Bluetooth-om ili Wi-Fi-jem mogu biti zloupotrebljeni za potpuno preuzimanje modernih smart-TV uređaja**. Napad povezuje IR service codes sa visokim privilegijama i autentifikovane Bluetooth pakete, zaobilazeći izolaciju kanala i omogućavajući proizvoljno pokretanje aplikacija, aktiviranje mikrofona ili vraćanje uređaja na fabrička podešavanja bez fizičkog pristupa. Potvrđeno je da je ranjivo osam mainstream TV uređaja različitih proizvođača — uključujući Samsung model koji tvrdi da je usklađen sa standardom ISO/IEC 27001. Ublažavanje rizika zahteva vendor firmware ispravke ili potpuno onemogućavanje nekorišćenih IR prijemnika.<sup>[[2]](#references)</sup>

### Eksfiltracija podataka iz air-gapped sistema pomoću IR LED dioda (aIR-Jumper family)

Sigurnosne kamere, ruteri, pa čak i zlonamerni USB stikovi često sadrže **IR LED diode za noćni vid**. Istraživanja pokazuju da malware može da moduliše ove LED diode (<10–20 kbit/s uz jednostavan OOK) kako bi **eksfiltrirao tajne kroz zidove i prozore** do spoljne kamere udaljene desetinama metara. Pošto se svetlost nalazi izvan vidljivog spektra, operateri je retko primete. Mere zaštite:

* Fizički zaštitite ili uklonite IR LED diode u osetljivim područjima
* Pratite duty-cycle LED diode kamere i integritet firmware-a
* Postavite IR-cut filtere na prozore i nadzorne kamere

Napadač takođe može da koristi snažne IR projektore za **infiltraciju** komandi u mrežu tako što će slati podatke treperenjem prema nezaštićenim kamerama.

### Brute-force napadi velikog dometa i prošireni protokoli uz Flipper Zero 1.0

Firmware 1.0 (septembar 2024) dodao je **desetine dodatnih IR protokola i opcione module eksternih pojačivača**. U kombinaciji sa universal-remote brute-force režimom, Flipper može da isključi ili rekonfiguriše većinu javnih TV/AC uređaja sa udaljenosti do 30 m pomoću diode velike snage.

---

## Alati i praktični primeri <a href="#tooling" id="tooling"></a>

### Hardver

* **Flipper Zero** – prenosivi transceiver sa režimima za učenje, replay i dictionary-bruteforce (pogledajte iznad).
* **Arduino / ESP32** + IR LED / TSOP38xx prijemnik – jeftin DIY analizator/transmiter. Kombinujte ga sa `Arduino-IRremote` bibliotekom (v4.x podržava više od 40 protokola).
* **Logic analysers** (Saleae/FX2) – hvataju sirove vremenske intervale kada je protokol nepoznat.
* **Pametni telefoni sa IR-blasterom** (npr. Xiaomi) – brzi field test, ali ograničenog dometa.

### Softver

* **`Arduino-IRremote`** – aktivno održavana C++ biblioteka:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
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

## Odbrambene mere <a href="#defense" id="defense"></a>

* Onemogućite ili prekrijte IR prijemnike na uređajima postavljenim na javnim mestima kada nisu potrebni.
* Uvedite *pairing* ili kriptografske provere između smart-TV uređaja i daljinskih upravljača; izolujte privilegovane „service“ kodove.
* Postavite IR-cut filtere ili detektore kontinuiranog talasa oko poverljivih područja kako biste prekinuli optičke covert kanale.
* Pratite integritet firmware-a kamera/IoT uređaja koji imaju kontrolisive IR LED diode.

## Reference

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen: Smart TV hijacking via remote control mimicry](https://arxiv.org/abs/2210.03014)

{{#include ../../banners/hacktricks-training.md}}
