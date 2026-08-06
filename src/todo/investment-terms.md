# Investicioni termini

{{#include ../banners/hacktricks-training.md}}

## Spot

Ovo je najosnovniji način trgovanja. Možete **navesti količinu sredstva i cenu** po kojoj želite da kupite ili prodate, a kada se ta cena dostigne, transakcija se izvršava.

Obično možete koristiti i **trenutnu tržišnu cenu** kako bi se transakcija izvršila što je brže moguće po trenutnoj ceni.

**Stop Loss - Limit**: Takođe možete navesti količinu i cenu sredstava za kupovinu ili prodaju, uz istovremeno navođenje niže cene po kojoj će se kupovina ili prodaja izvršiti ako se ta cena dostigne (kako bi se zaustavili gubici).

## Futures

Futures je ugovor kojim se dve strane dogovaraju da **nešto kupe u budućnosti po fiksnoj ceni**. Na primer, prodaja 1 bitcoina za 6 meseci po ceni od 70.000$.

Očigledno, ako nakon 6 meseci vrednost bitcoina bude 80.000$, prodavac gubi novac, a kupac ga dobija. Ako nakon 6 meseci vrednost bitcoina bude 60.000$, dešava se suprotno.

Međutim, ovo je zanimljivo, na primer, za preduzeća koja proizvode određeni proizvod i moraju da budu sigurna da će moći da ga prodaju po ceni koja pokriva troškove. Takođe je korisno za preduzeća koja žele da obezbede fiksne cene u budućnosti, čak i ako su one više.

Ipak, na berzama se ovo obično koristi za pokušaj ostvarivanja profita.

* Imajte na umu da "Long position" znači da neko ulaže uz očekivanje da će cena porasti
* Dok "short position" znači da neko ulaže uz očekivanje da će cena pasti

### Hedging With Futures <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Ako se menadžer fonda plaši da će neke akcije pasti, može zauzeti kratku poziciju na sredstvima kao što su bitcoini ili futures ugovori za S\&P 500. Ovo bi bilo slično kupovini ili posedovanju određenih sredstava i sklapanju ugovora o njihovoj prodaji u budućnosti po višoj ceni.

U slučaju pada cene, menadžer fonda će ostvariti dobit jer će sredstva prodati po višoj ceni. Ako cena sredstava poraste, menadžer neće ostvariti tu dobit, ali će i dalje zadržati svoja sredstva.

### Perpetual Futures

**Ovo su "futures" ugovori koji traju neograničeno** (bez datuma isteka ugovora). Veoma ih je često naći, na primer, na crypto berzama, gde možete ulaziti u futures pozicije i izlaziti iz njih na osnovu cene crypto valuta.

Imajte na umu da u ovim slučajevima dobici i gubici mogu nastajati u realnom vremenu: ako cena poraste za 1%, dobijate 1%; ako cena padne za 1%, gubite 1%.

### Futures with Leverage

**Leverage** vam omogućava da kontrolišete veću poziciju na tržištu sa manjom količinom novca. U osnovi vam omogućava da "uložite" mnogo više novca nego što imate, rizikujući samo novac koji zaista posedujete.

Na primer, ako otvorite futures poziciju na BTC/USDT sa 100$ i leverage-om od 50x, to znači da biste, ako cena poraste za 1%, ostvarili dobit od 1x50 = 50% početnog uloga (50$). Prema tome, imali biste 150$.\
Međutim, ako cena padne za 1%, izgubićete 50% svojih sredstava (u ovom slučaju 59$). Ako cena padne za 2%, izgubićete ceo ulog (2x50 = 100%).

Dakle, leverage omogućava kontrolu količine novca koji ulažete, uz istovremeno povećanje dobitaka i gubitaka.

## Razlike između Futures i Options

Glavna razlika između futures ugovora i opcija jeste u tome što je ugovor za kupca opcionalan: on može odlučiti da li će ga izvršiti ili ne (obično će to učiniti samo ako će od toga imati koristi). Prodavac mora da proda ako kupac želi da iskoristi opciju.\
Međutim, kupac će prodavcu platiti određenu naknadu za otvaranje opcije (tako prodavac, koji očigledno preuzima veći rizik, počinje da zarađuje).

### 1. **Obaveza naspram prava:**

* **Futures:** Kada kupite ili prodate futures ugovor, sklapate **obavezujući sporazum** o kupovini ili prodaji sredstva po određenoj ceni na određeni budući datum. I kupac i prodavac imaju **obavezu** da ispune ugovor po isteku (osim ako se ugovor ne zatvori pre toga).
* **Options:** Kod opcija imate **pravo, ali ne i obavezu**, da kupite (u slučaju **call opcije**) ili prodate (u slučaju **put opcije**) sredstvo po određenoj ceni pre određenog datuma isteka ili na taj datum. **Kupac** ima mogućnost da izvrši opciju, dok je **prodavac** obavezan da izvrši transakciju ako kupac odluči da iskoristi opciju.

### 2. **Rizik:**

* **Futures:** I kupac i prodavac preuzimaju **neograničen rizik** jer imaju obavezu da izvrše ugovor. Rizik predstavlja razliku između dogovorene cene i tržišne cene na datum isteka.
* **Options:** Rizik kupca ograničen je na **premiju** plaćenu za kupovinu opcije. Ako se tržište ne kreće u korist imaoca opcije, on jednostavno može pustiti da opcija istekne. Međutim, **prodavac** (izdavalac) opcije ima neograničen rizik ako se tržište značajno kreće protiv njega.

### 3. **Trošak:**

* **Futures:** Ne postoji početni trošak osim margine potrebne za držanje pozicije, jer i kupac i prodavac imaju obavezu da završe transakciju.
* **Options:** Kupac mora unapred da plati **premiju opcije** za pravo da izvrši opciju. Ova premija predstavlja trošak opcije.

### 4. **Potencijalni profit:**

* **Futures:** Profit ili gubitak zasniva se na razlici između tržišne cene po isteku i dogovorene cene iz ugovora.
* **Options:** Kupac ostvaruje profit kada se tržište povoljno pomeri iznad izvršne cene za iznos veći od plaćene premije. Prodavac ostvaruje profit zadržavanjem premije ako se opcija ne iskoristi.

{{#include ../banners/hacktricks-training.md}}
