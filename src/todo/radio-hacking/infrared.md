# Infrared

{{#include ../../banners/hacktricks-training.md}}

## Kako funkcioniše infracrveno svetlo <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infracrveno svetlo je nevidljivo ljudima**. IR talasna dužina je od **0.7 do 1000 mikrona**. Daljinski upravljači koriste IR signal za prenos podataka i rade u opsegu talasnih dužina od 0.75..1.4 mikrona. Mikrokontroler u daljinskom upravljaču čini da infracrvena LED dioda trepće sa određenom frekvencijom, pretvarajući digitalni signal u IR signal.

Za prijem IR signala koristi se **fotoreceptor**. On **pretvara IR svetlost u naponske pulse**, koji su već **digitalni signali**. Obično, unutar prijemnika postoji **filter za tamnu svetlost**, koji propušta **samo željenu talasnu dužinu** i eliminiše šum.

### Različiti IR protokoli <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protokoli se razlikuju u 3 faktora:

- kodiranje bitova
- struktura podataka
- nosna frekvencija — često u opsegu 36..38 kHz

#### Načini kodiranja bitova <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Kodiranje razmaka impulsa**

Bitovi se kodiraju modulacijom trajanja razmaka između impulsa. Širina samog impulsa je konstantna.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Kodiranje širine impulsa**

Bitovi se kodiraju modulacijom širine impulsa. Širina razmaka nakon burst-a impulsa je konstantna.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Kodiranje faze**

Poznato je i kao Mančestersko kodiranje. Logička vrednost se definiše polaritetom prelaza između burst-a impulsa i razmaka. "Razmak do burst-a impulsa" označava logiku "0", "burst impulsa do razmaka" označava logiku "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombinacija prethodnih i drugih egzotika**

> [!TIP]
> Postoje IR protokoli koji **pokušavaju da postanu univerzalni** za nekoliko tipova uređaja. Najpoznatiji su RC5 i NEC. Nažalost, najpoznatiji **ne znači i najčešći**. U mom okruženju, sreo sam samo dva NEC daljinska upravljača i nijedan RC5.
>
> Proizvođači vole da koriste svoje jedinstvene IR protokole, čak i unutar iste grupe uređaja (na primer, TV kutije). Stoga, daljinski upravljači različitih kompanija, a ponekad i različitih modela iz iste kompanije, nisu u stanju da rade sa drugim uređajima istog tipa.

### Istraživanje IR signala

Najpouzdaniji način da se vidi kako izgleda IR signal daljinskog upravljača je korišćenje osciloskopa. On ne demodulira ili invertuje primljeni signal, već ga prikazuje "kakav jeste". Ovo je korisno za testiranje i otklanjanje grešaka. Prikazaću očekivani signal na primeru NEC IR protokola.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Obično, na početku kodiranog paketa postoji preambula. Ovo omogućava prijemniku da odredi nivo pojačanja i pozadinsku buku. Postoje i protokoli bez preamble, na primer, Sharp.

Zatim se prenose podaci. Struktura, preambula i način kodiranja bitova određeni su specifičnim protokolom.

**NEC IR protokol** sadrži kratku komandu i kod ponavljanja, koji se šalje dok je dugme pritisnuto. I komanda i kod ponavljanja imaju istu preambulu na početku.

NEC **komanda**, pored preamble, sastoji se od bajta adrese i bajta broja komande, po kojima uređaj razume šta treba da se izvrši. Bajti adrese i broja komande su duplicirani sa inverznim vrednostima, kako bi se proverila celovitost prenosa. Na kraju komande postoji dodatni stop bit.

**Kod ponavljanja** ima "1" nakon preamble, što je stop bit.

Za **logiku "0" i "1"** NEC koristi kodiranje razmaka impulsa: prvo se prenosi burst impulsa nakon kojeg sledi pauza, čija dužina postavlja vrednost bita.

### Klimatizacije

Za razliku od drugih daljinskih upravljača, **klimatizacije ne prenose samo kod pritisnutog dugmeta**. Takođe **prenose sve informacije** kada je dugme pritisnuto kako bi se osiguralo da su **klimatizacijska mašina i daljinski upravljač sinhronizovani**.\
To će sprečiti da mašina postavljena na 20ºC bude povećana na 21ºC jednim daljinskim upravljačem, a zatim kada se koristi drugi daljinski upravljač, koji još uvek ima temperaturu od 20ºC, da se poveća temperatura, ona će "povećati" na 21ºC (a ne na 22ºC misleći da je na 21ºC).

---

## Napadi i ofanzivna istraživanja <a href="#attacks" id="attacks"></a>

Možete napasti infracrveno svetlo sa Flipper Zero:

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Preuzimanje Smart-TV / Set-top Box (EvilScreen)

Nedavni akademski rad (EvilScreen, 2022) pokazao je da **višekanalni daljinski upravljači koji kombinuju infracrveno sa Bluetooth-om ili Wi-Fi-jem mogu biti zloupotrebljeni za potpuno preuzimanje modernih pametnih televizora**. Napad povezuje IR servisne kodove visokih privilegija sa autentifikovanim Bluetooth paketima, zaobilazeći izolaciju kanala i omogućavajući pokretanje proizvoljnih aplikacija, aktivaciju mikrofona ili fabričko resetovanje bez fizičkog pristupa. Osam mainstream televizora različitih proizvođača — uključujući Samsung model koji tvrdi da je u skladu sa ISO/IEC 27001 — potvrđeno je kao ranjivo. Ublažavanje zahteva ispravke firmvera od strane proizvođača ili potpuno onemogućavanje neiskorišćenih IR prijemnika.

### Ekstrakcija podataka iz vazduha putem IR LED dioda (aIR-Jumper porodica)

Sigurnosne kamere, ruteri ili čak zlonamerni USB stikovi često uključuju **infracrvene LED diode za noćno osvetljenje**. Istraživanja pokazuju da zlonamerni softver može modulirati ove LED diode (<10–20 kbit/s sa jednostavnim OOK) kako bi **izvukao tajne kroz zidove i prozore** do spoljne kamere postavljene na desetine metara daleko. Pošto je svetlost izvan vidljivog spektra, operateri retko primete. Protivmere:

* Fizički zaštititi ili ukloniti IR LED diode u osetljivim područjima
* Pratiti radni ciklus LED dioda kamera i integritet firmvera
* Postaviti IR-cut filtere na prozore i nadzorne kamere

Napadač takođe može koristiti jake IR projektore da **infiltrira** komande u mrežu bljeskajući podatke nazad do nesigurnih kamera.

### Dugoročni brute-force i prošireni protokoli sa Flipper Zero 1.0

Firmver 1.0 (septembar 2024) dodao je **desetine dodatnih IR protokola i opcionih spoljašnjih pojačivača**. U kombinaciji sa univerzalnim daljinskim upravljačem u režimu brute-force, Flipper može onemogućiti ili rekonfigurisati većinu javnih televizora/klimatizacija sa udaljenosti do 30 m koristeći diodu velike snage.

---

## Alati i praktični primeri <a href="#tooling" id="tooling"></a>

### Hardver

* **Flipper Zero** – prenosivi transiver sa režimima učenja, ponavljanja i rečnika-brute-force (vidi iznad).
* **Arduino / ESP32** + IR LED / TSOP38xx prijemnik – jeftin DIY analizer/trasnmitter. Kombinujte sa `Arduino-IRremote` bibliotekom (v4.x podržava >40 protokola).
* **Logički analizeri** (Saleae/FX2) – hvataju sirove vremenske okvire kada je protokol nepoznat.
* **Pametni telefoni sa IR blasterom** (npr., Xiaomi) – brzi terenski test, ali ograničenog dometa.

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
* **IRscrutinizer / AnalysIR** – GUI dekoderi koji uvoze sirove snimke i automatski identifikuju protokol + generišu Pronto/Arduino kod.
* **LIRC / ir-keytable (Linux)** – primanje i injektovanje IR sa komandne linije:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Odbrambene mere <a href="#defense" id="defense"></a>

* Onemogućiti ili pokriti IR prijemnike na uređajima postavljenim u javnim prostorima kada nisu potrebni.
* Sprovoditi *pariranje* ili kriptografske provere između pametnih televizora i daljinskih upravljača; izolovati privilegovane “servisne” kodove.
* Postaviti IR-cut filtere ili detektore kontinuiranih talasnih dužina oko klasifikovanih područja kako bi se prekinuli optički tajni kanali.
* Pratiti integritet firmvera kamera/IoT uređaja koji izlažu kontrolisane IR LED diode.

## Reference

- [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- EvilScreen: Preuzimanje pametnog TV-a putem imitacije daljinskog upravljača (arXiv 2210.03014)

{{#include ../../banners/hacktricks-training.md}}
