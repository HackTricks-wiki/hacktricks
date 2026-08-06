# Infracrveno

{{#include ../../banners/hacktricks-training.md}}

## Kako infracrveno funkcioniše <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infracrvena svetlost je nevidljiva ljudima**. IR talasna dužina je od **0.7 do 1000 mikrona**. Kućni daljinski upravljači koriste IR signal za prenos podataka i rade u opsegu talasnih dužina od 0.75..1.4 mikrona. Mikrokontroler u daljinskom upravljaču izaziva treperenje infracrvene LED diode na određenoj frekvenciji, pretvarajući digitalni signal u IR signal.

Za prijem IR signala koristi se **fotoprijemnik**. On **pretvara IR svetlost u naponske impulse**, koji su već **digitalni signali**. Obično se unutar prijemnika nalazi **filter za tamnu svetlost**, koji propušta **samo željenu talasnu dužinu** i uklanja šum.<sup>[[1]](#references)</sup>

### Različiti IR protokoli <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protokoli se razlikuju po 3 faktora:<sup>[[1]](#references)</sup>

- kodiranje bitova
- struktura podataka
- noseća frekvencija — često u opsegu 36..38 kHz

#### Načini kodiranja bitova <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bitovi se kodiraju modulacijom trajanja razmaka između impulsa. Širina samog impulsa je konstantna.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bitovi se kodiraju modulacijom širine impulsa. Širina razmaka nakon burst-a impulsa je konstantna.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Poznato je i kao Manchester encoding. Logička vrednost se određuje polaritetom prelaza između burst-a impulsa i razmaka. „Razmak ka burst-u impulsa“ označava logiku „0“, a „burst impulsa ka razmaku“ označava logiku „1“.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombinacija prethodnih i drugih egzotičnih metoda**

> [!TIP]
> Postoje IR protokoli koji **pokušavaju da postanu univerzalni** za više vrsta uređaja. Najpoznatiji su RC5 i NEC. Nažalost, to što je nešto **najpoznatije ne znači da je i najčešće**. U svom okruženju sam naišao na samo dva NEC daljinska upravljača i nijedan RC5.
>
> Proizvođači vole da koriste sopstvene jedinstvene IR protokole, čak i unutar istog opsega uređaja (na primer, TV-box uređaja). Zbog toga daljinski upravljači različitih kompanija, a ponekad i različitih modela iste kompanije, ne mogu da rade sa drugim uređajima iste vrste.

### Istraživanje IR signala

Najpouzdaniji način da se vidi kako IR signal daljinskog upravljača izgleda jeste korišćenje osciloskopa. On ne demoduliše niti invertuje primljeni signal, već ga samo prikazuje „takvog kakav jeste“. Ovo je korisno za testiranje i debugging. Prikazaću očekivani signal na primeru NEC IR protokola.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Obično se na početku kodiranog paketa nalazi preambula. Ona prijemniku omogućava da odredi nivo pojačanja i pozadinu. Postoje i protokoli bez preambule, na primer Sharp.

Zatim se prenose podaci. Strukturu, preambulu i metod kodiranja bitova određuje konkretni protokol.

**NEC IR protokol** sadrži kratku komandu i repeat code, koji se šalje dok je dugme pritisnuto. I komanda i repeat code na početku imaju istu preambulu.

NEC **komanda**, pored preambule, sadrži bajt adrese i bajt broja komande, na osnovu kojih uređaj razume šta treba izvršiti. Bajtovi adrese i broja komande duplirani su inverznim vrednostima radi provere integriteta prenosa. Na kraju komande nalazi se dodatni stop bit.

**Repeat code** nakon preambule ima „1“, što predstavlja stop bit.

Za **logike „0“ i „1“** NEC koristi Pulse Distance Encoding: najpre se prenosi burst impulsa, nakon čega sledi pauza čija dužina određuje vrednost bita.

### Klima-uređaji

Za razliku od drugih daljinskih upravljača, **klima-uređaji ne prenose samo kod pritisnutog dugmeta**. Oni takođe **prenose sve informacije** prilikom pritiska na dugme kako bi se obezbedilo da su **klima-uređaj i daljinski upravljač sinhronizovani**.\
Time se sprečava da se temperatura uređaja podešena na 20ºC jednim daljinskim upravljačem poveća na 21ºC, a zatim da se, kada se drugim daljinskim upravljačem, koji i dalje ima temperaturu podešenu na 20ºC, ponovo poveća temperatura, ona „poveća“ na 21ºC (umesto na 22ºC, jer drugi daljinski upravljač misli da je temperatura 21ºC).<sup>[[1]](#references)</sup>

---

## Attacks i Offensive Research <a href="#attacks" id="attacks"></a>

Infrared možete napasti pomoću Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Preuzimanje Smart-TV / Set-top Box uređaja (EvilScreen)

Nedavna akademska istraživanja (EvilScreen, 2022) pokazala su da **višekanalni daljinski upravljači koji kombinuju Infrared sa Bluetooth-om ili Wi-Fi-jem mogu biti zloupotrebljeni za potpuno preuzimanje kontrole nad modernim smart-TV uređajima**. Napad povezuje IR service kodove visokih privilegija sa autentifikovanim Bluetooth paketima, zaobilazeći izolaciju kanala i omogućavajući proizvoljno pokretanje aplikacija, aktiviranje mikrofona ili factory-reset bez fizičkog pristupa. Potvrđeno je da je osam mainstream TV uređaja različitih proizvođača — uključujući Samsung model koji tvrdi da je usklađen sa ISO/IEC 27001 — ranjivo. Mitigacija zahteva vendor firmware ispravke ili potpuno onemogućavanje nekorišćenih IR prijemnika.<sup>[[2]](#references)</sup>

### Exfiltration podataka iz air-gapped sistema putem IR LED dioda (aIR-Jumper family)

Security kamere, ruteri, pa čak i zlonamerni USB uređaji često sadrže **IR LED diode za noćno snimanje**. Istraživanja pokazuju da malware može modulirati ove LED diode (<10–20 kbit/s uz jednostavan OOK) kako bi **exfiltrirao tajne kroz zidove i prozore** do spoljne kamere udaljene desetinama metara.<sup>[[3]](#references)</sup> Pošto je svetlost izvan vidljivog spektra, operateri je retko primećuju. Counter-measures:

* Fizički zaštititi ili ukloniti IR LED diode u osetljivim oblastima
* Nadgledati duty-cycle LED diode kamere i integritet firmware-a
* Postaviti IR-cut filtere na prozore i surveillance kamere

Napadač takođe može koristiti snažne IR projektore za **infiltraciju** komandi u mrežu, emitovanjem podataka ka nesigurnim kamerama.

### Long-Range Brute-Force i Extended Protocols sa Flipper Zero 1.0

Firmware 1.0 (septembar 2024) dodao je **desetine dodatnih IR protokola i opcione spoljne amplifier module**. U kombinaciji sa universal-remote brute-force režimom, Flipper može da isključi ili rekonfiguriše većinu javno dostupnih TV/AC uređaja sa udaljenosti do 30 m, koristeći diodu velike snage.

---

## Alati i praktični primeri <a href="#tooling" id="tooling"></a>

### Hardver

* **Flipper Zero** – prenosivi transceiver sa režimima za learning, replay i dictionary-bruteforce (vidi iznad).
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – jeftin DIY analyzer/transmitter. Kombinovati sa `Arduino-IRremote` bibliotekom (v4.x podržava više od 40 protokola).
* **Logic analyzers** (Saleae/FX2) – hvataju raw timings kada je protokol nepoznat.
* **Smartphones sa IR-blasterom** (npr. Xiaomi) – brzi field test, ali ograničenog dometa.

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
* **IRscrutinizer / AnalysIR** – GUI decoders koji uvoze raw captures, automatski identifikuju protokol i generišu Pronto/Arduino kod.
* **LIRC / ir-keytable (Linux)** – primaju i ubacuju IR iz command line-a:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* Onemogućiti ili prekriti IR prijemnike na uređajima postavljenim u javnim prostorima kada nisu potrebni.
* Uvesti *pairing* ili kriptografske provere između smart-TV uređaja i daljinskih upravljača; izolovati privilegovane „service“ kodove.
* Postaviti IR-cut filtere ili continuous-wave detektore oko poverljivih oblasti kako bi se prekinuli optički covert channels.
* Nadgledati integritet firmware-a kamera/IoT uređaja koji imaju kontrolabilne IR LED diode.

## Reference

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)

{{#include ../../banners/hacktricks-training.md}}
