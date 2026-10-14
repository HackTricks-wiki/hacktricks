# Infracrveno

{{#include ../../banners/hacktricks-training.md}}

## Kako infracrveno zračenje funkcioniše <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infracrvena svetlost je nevidljiva ljudima**. Talasna dužina IR zračenja je od **0,7 do 1000 mikrona**. Kućni daljinski upravljači koriste IR signal za prenos podataka i rade u opsegu talasnih dužina od 0,75 do 1,4 mikrona. Mikrokontroler u daljinskom upravljaču uključuje i isključuje infracrvenu LED diodu na određenoj frekvenciji, pretvarajući digitalni signal u IR signal.

Za prijem IR signala koristi se **fotoprijemnik**. On **pretvara IR svetlost u naponske impulse**, koji su već **digitalni signali**. Obično se unutar prijemnika nalazi **filter za tamnu svetlost**, koji propušta **samo željenu talasnu dužinu** i uklanja šum.<sup>[[1]](#references)</sup>

### Različiti IR protokoli <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protokoli se razlikuju po 3 faktora:<sup>[[1]](#references)</sup>

- kodiranje bitova
- struktura podataka
- noseća frekvencija — često u opsegu od 36 do 38 kHz

#### Načini kodiranja bitova <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Kodiranje razmakom između impulsa**

Bitovi se kodiraju modulacijom trajanja razmaka između impulsa. Širina samog impulsa je konstantna.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Kodiranje širinom impulsa**

Bitovi se kodiraju modulacijom širine impulsa. Širina razmaka nakon niza impulsa je konstantna.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Fazno kodiranje**

Poznato je i kao Manchester kodiranje. Logička vrednost određuje se polaritetom prelaza između niza impulsa i razmaka. „Razmak ka nizu impulsa” označava logičku „0”, a „niz impulsa ka razmaku” označava logičku „1”.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombinacija prethodnih metoda i drugih egzotičnih načina**

> [!TIP]
> Postoje IR protokoli koji **nastoje da postanu univerzalni** za više vrsta uređaja. Najpoznatiji su RC5 i NEC. Nažalost, **najpoznatiji ne znači i najčešći**. U svom okruženju sam naišao na samo dva NEC daljinska upravljača, a nijedan RC5.
>
> Proizvođači rado koriste sopstvene jedinstvene IR protokole, čak i za istu grupu uređaja (na primer, TV box uređaje). Zato daljinski upravljači različitih kompanija, a ponekad i različitih modela iste kompanije, ne mogu da rade sa drugim uređajima iste vrste.

### Istraživanje IR signala

Najpouzdaniji način da vidite kako izgleda IR signal daljinskog upravljača jeste da upotrebite osciloskop. On ne demoduliše niti invertuje primljeni signal, već ga prikazuje „takvog kakav jeste”. Ovo je korisno za testiranje i otklanjanje grešaka. Očekivani signal prikazaću na primeru NEC IR protokola.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Na početku kodiranog paketa obično se nalazi uvodna sekvenca. Ona omogućava prijemniku da odredi nivo pojačanja i pozadinski signal. Postoje i protokoli bez uvodne sekvence, na primer Sharp.

Zatim se prenose podaci. Struktura, uvodna sekvenca i način kodiranja bitova zavise od konkretnog protokola.

**NEC IR protokol** sadrži kratku komandu i kod za ponavljanje, koji se šalje dok je dugme pritisnuto. I komanda i kod za ponavljanje imaju istu uvodnu sekvencu.

Pored uvodne sekvence, NEC **komanda** se sastoji od bajta adrese i bajta broja komande, na osnovu kojih uređaj zna šta treba da izvrši. Bajtovi adrese i broja komande duplirani su sa inverznim vrednostima radi provere integriteta prenosa. Na kraju komande nalazi se dodatni stop-bit.

**Kod za ponavljanje** sadrži „1” nakon uvodne sekvence, što predstavlja stop-bit.

Za **logičke „0” i „1”** NEC koristi kodiranje razmakom između impulsa: najpre se prenosi niz impulsa, a zatim pauza čija dužina određuje vrednost bita.

### Klima-uređaji

Za razliku od drugih daljinskih upravljača, **daljinski upravljači za klima-uređaje ne prenose samo kod pritisnutog dugmeta**. Oni takođe **prenose sve informacije** prilikom pritiska na dugme kako bi se osigurala **sinhronizacija klima-uređaja i daljinskog upravljača**.\
Tako se sprečava da uređaj podešen na 20 ºC jednim daljinskim upravljačem bude podešen na 21 ºC, a da drugi daljinski upravljač, koji i dalje prikazuje 20 ºC, zatim ponovo „poveća” temperaturu na 21 ºC (umesto na 22 ºC, jer misli da je temperatura 21 ºC).<sup>[[1]](#references)</sup>

---

## Napadi i ofanzivno istraživanje <a href="#attacks" id="attacks"></a>

Infracrveno možete napasti pomoću Flipper Zero:

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Preuzimanje kontrole nad Smart-TV / set-top box uređajima (EvilScreen)

Nedavna akademska studija (EvilScreen, 2022) pokazala je da **višekanalni daljinski upravljači koji kombinuju infracrvenu vezu sa Bluetooth-om ili Wi-Fi mrežom mogu da se zloupotrebe za potpuno preuzimanje kontrole nad modernim Smart-TV uređajima**. Napad povezuje IR servisne kodove sa visokim privilegijama sa autentifikovanim Bluetooth paketima, zaobilazi izolaciju kanala i omogućava proizvoljno pokretanje aplikacija, aktiviranje mikrofona ili vraćanje na fabrička podešavanja bez fizičkog pristupa. Potvrđena je ranjivost osam vodećih televizora različitih proizvođača, uključujući Samsung model za koji se tvrdi da ispunjava standard ISO/IEC 27001. Zaštita zahteva ispravke firmvera proizvođača ili potpuno isključivanje neiskorišćenih IR prijemnika.<sup>[[2]](#references)</sup>

### Eksfiltracija podataka preko IR LED dioda iz sistema izolovanih od mreže (porodica aIR-Jumper)

Bezbednosne kamere često imaju **IR LED diode za noćno snimanje**. Prototip aIR-Jumper pokazao je da malware koji kontroliše te LED diode može **da eksfiltrira tajne kroz prozore** do spoljne kamere brzinom do **20 bit/s po nadzornoj kameri**, na udaljenostima od više desetina metara. U obrnutom smeru, istraživači su demonstrirali infiltraciju brzinom većom od **100 bit/s**, na udaljenostima od nekoliko stotina metara do nekoliko kilometara.<sup>[[3]](#references)</sup> Pošto je svetlost izvan vidljivog spektra, operateri možda neće primetiti aktivnost. Mere zaštite uključuju:

* Fizički zaštititi ili ukloniti IR LED diode u osetljivim područjima
* Nadzirati radni ciklus LED dioda kamere i integritet firmvera
* Postaviti IR filtere na prozore i nadzorne kamere

Napadač može da upotrebi i snažne IR projektore za **infiltraciju** komandi u mrežu tako što će slati podatke nazad preko nebezbednih kamera.

### Brute-force na velikim udaljenostima i prošireni protokoli uz Flipper Zero 1.0

Firmver 1.0 (septembar 2024) proširio je biblioteku univerzalnih daljinskih upravljača i dodao dinamičko učitavanje infracrvenih datoteka resursa sa microSD kartice.<sup>[[4]](#references)</sup> Funkcije učenja i univerzalnog daljinskog upravljača mogu da ponove ili isprobaju poznate komande na obližnjim televizorima i klima-uređajima. Domet u velikoj meri zavisi od predajnika, optike, ambijentalnog svetla i prijemnika; spoljašnji IR hardver može da ga poveća, ali ne treba pretpostaviti fiksnu udaljenost.

---

## Alati i praktični primeri <a href="#tooling" id="tooling"></a>

### Hardver

* **Flipper Zero** – prenosivi primopredajnik sa režimima učenja, ponavljanja i brute-force napada na osnovu rečnika (pogledajte iznad).
* **Arduino / ESP32** + IR LED dioda / TSOP38xx prijemnik – jeftin analizator/predajnik za samostalnu izradu. Koristite zajedno sa bibliotekom `Arduino-IRremote` (v4.x podržava više od 40 protokola).
* **Logički analizatori** (Saleae/FX2) – snimaju sirova vremena kada protokol nije poznat.
* **Pametni telefoni sa IR blasterom** (npr. Xiaomi) – brz terenski test, ali sa ograničenim dometom.

### Softver

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
* **LIRC / ir-keytable (Linux)** – primanje i emitovanje IR signala iz komandne linije:
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## Odbrambene mere <a href="#defense" id="defense"></a>

* Onemogućite IR prijemnike ili ih prekrijte na uređajima postavljenim na javnim mestima kada nisu potrebni.
* Zahtevajte *uparivanje* ili kriptografske provere između smart-TV uređaja i daljinskih upravljača; izolujte privilegovane „servisne“ kodove.
* Postavite IR-cut filtere ili detektore kontinuiranog talasa oko klasifikovanih područja kako biste prekinuli optičke skrivene kanale.
* Nadgledajte integritet firmware-a kamera/IoT uređaja koji imaju IR LED diode kojima se može upravljati.

## References

- [1] [Flipper Zero blog objava o infracrvenom zračenju](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Otmica smart-TV uređaja pomoću oponašanja višekanalnog daljinskog upravljanja (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Skrivena eksfiltracija/infiltracija preko vazdušnog procepa pomoću sigurnosnih kamera i infracrvenog zračenja (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero blog - objavljen firmware 1.0](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - dokumentacija o upotrebi i protokolu](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
