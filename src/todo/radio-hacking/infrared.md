# Infrared

{{#include ../../banners/hacktricks-training.md}}

## Kako funkcioniše infracrveno <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infracrvena svetlost je nevidljiva ljudima**. IR talasna dužina je od **0.7 do 1000 mikrona**. Daljinski upravljači koriste IR signal za prenos podataka i rade u opsegu talasnih dužina od 0.75..1.4 mikrona. Mikrokontroler u daljinskom upravljaču čini da infracrveni LED trepće sa određenom frekvencijom, pretvarajući digitalni signal u IR signal.

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

> [!NOTE]
> Postoje IR protokoli koji **pokušavaju da postanu univerzalni** za nekoliko tipova uređaja. Najpoznatiji su RC5 i NEC. Nažalost, najpoznatiji **ne znači i najčešći**. U mojoj okolini, sreo sam samo dva NEC daljinska upravljača i nijedan RC5.
>
> Proizvođači vole da koriste svoje jedinstvene IR protokole, čak i unutar iste grupe uređaja (na primer, TV kutije). Stoga, daljinski upravljači iz različitih kompanija, a ponekad i iz različitih modela iste kompanije, nisu u stanju da rade sa drugim uređajima istog tipa.

### Istraživanje IR signala

Najpouzdaniji način da se vidi kako izgleda IR signal daljinskog upravljača je korišćenje osciloskopa. On ne demodulira ili invertuje primljeni signal, već ga prikazuje "kakav jeste". Ovo je korisno za testiranje i otklanjanje grešaka. Prikazaću očekivani signal na primeru NEC IR protokola.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Obično, na početku kodiranog paketa postoji preambula. Ovo omogućava prijemniku da odredi nivo pojačanja i pozadinsku buku. Postoje i protokoli bez preamble, na primer, Sharp.

Zatim se prenose podaci. Struktura, preambula i način kodiranja bitova određeni su specifičnim protokolom.

**NEC IR protokol** sadrži kratku komandu i kod ponavljanja, koji se šalje dok je dugme pritisnuto. I komanda i kod ponavljanja imaju istu preambulu na početku.

NEC **komanda**, pored preamble, sastoji se od bajta adrese i bajta broja komande, pomoću kojih uređaj razume šta treba da se izvrši. Bajti adrese i broja komande su duplicirani sa inverznim vrednostima, kako bi se proverila celovitost prenosa. Na kraju komande postoji dodatni stop bit.

**Kod ponavljanja** ima "1" nakon preamble, što je stop bit.

Za **logiku "0" i "1"** NEC koristi kodiranje razmaka impulsa: prvo se prenosi burst impulsa nakon kojeg sledi pauza, čija dužina postavlja vrednost bita.

### Klimatizacije

Za razliku od drugih daljinskih upravljača, **klimatizacije ne prenose samo kod pritisnutog dugmeta**. Takođe **prenose sve informacije** kada je dugme pritisnuto kako bi se osiguralo da su **klimatizacijska mašina i daljinski upravljač sinhronizovani**.\
To će sprečiti da mašina postavljena na 20ºC bude povećana na 21ºC jednim daljinskim upravljačem, a zatim kada se koristi drugi daljinski upravljač, koji još uvek ima temperaturu od 20ºC, da se poveća još više temperatura, ona će "povećati" na 21ºC (a ne na 22ºC misleći da je na 21ºC).

### Napadi

Možete napasti infracrveno sa Flipper Zero:

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

## Reference

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../banners/hacktricks-training.md}}
