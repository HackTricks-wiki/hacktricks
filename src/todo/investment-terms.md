# Investment Terms

{{#include /banners/hacktricks-training.md}}

## Spot

Ovo je najosnovniji način trgovanja. Možete **naznačiti količinu imovine i cenu** koju želite da kupite ili prodate, i kada god ta cena bude dostignuta, operacija se izvršava.

Obično možete koristiti i **trenutnu tržišnu cenu** kako biste izvršili transakciju što je brže moguće po trenutnoj ceni.

**Stop Loss - Limit**: Takođe možete naznačiti količinu i cenu imovine za kupovinu ili prodaju, dok takođe naznačavate nižu cenu za kupovinu ili prodaju u slučaju da bude dostignuta (da biste zaustavili gubitke).

## Futures

Futures je ugovor u kojem se 2 strane dogovaraju da **kupe nešto u budućnosti po fiksnoj ceni**. Na primer, da prodaju 1 bitcoin za 6 meseci po ceni od 70.000$.

Očigledno, ako za 6 meseci vrednost bitcoina bude 80.000$, prodavac gubi novac, a kupac zarađuje. Ako za 6 meseci vrednost bitcoina bude 60.000$, dešava se suprotno.

Međutim, ovo je zanimljivo, na primer, za preduzeća koja proizvode proizvod i treba da imaju sigurnost da će moći da ga prodaju po ceni koja pokriva troškove. Ili preduća koja žele da obezbede fiksne cene u budućnosti za nešto čak i ako su više.

Iako se na berzama ovo obično koristi da bi se pokušalo ostvariti profit.

* Imajte na umu da "Long pozicija" znači da neko veruje da će cena rasti
* Dok "short pozicija" znači da neko veruje da će cena opasti

### Hedging With Futures <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Ako je menadžer fonda zabrinut da će neke akcije opasti, može zauzeti short poziciju na nekim sredstvima kao što su bitcoini ili S&P 500 futures ugovori. Ovo bi bilo slično kupovini ili posedovanju nekih sredstava i kreiranju ugovora o prodaji tih sredstava u budućem vremenu po višoj ceni.

U slučaju da cena opadne, menadžer fonda će ostvariti dobit jer će prodati sredstva po višoj ceni. Ako cena sredstava poraste, menadžer neće ostvariti tu dobit, ali će i dalje zadržati svoja sredstva.

### Perpetual Futures

**Ovo su "futures" koji traju neodređeno** (bez datuma završetka ugovora). Veoma je uobičajeno naći ih, na primer, na kripto berzama gde možete ulaziti i izlaziti iz futures-a na osnovu cene kriptovaluta.

Imajte na umu da u ovim slučajevima dobit i gubitak mogu biti u realnom vremenu, ako cena poraste za 1%, vi dobijate 1%, ako cena opadne za 1%, izgubićete to.

### Futures with Leverage

**Leverage** vam omogućava da kontrolišete veću poziciju na tržištu sa manjim iznosom novca. U suštini, omogućava vam da "kladite" mnogo više novca nego što imate, rizikujući samo novac koji zapravo imate.

Na primer, ako otvorite futures poziciju u BTC/USDT sa 100$ uz 50x leverage, to znači da ako cena poraste za 1%, vi biste zarađivali 1x50 = 50% od vaše početne investicije (50$). I stoga ćete imati 150$.\
Međutim, ako cena opadne za 1%, izgubićete 50% svojih sredstava (59$ u ovom slučaju). A ako cena opadne za 2%, izgubićete celu svoju opkladu (2x50 = 100%).

Dakle, leverage omogućava kontrolu iznosa novca koji ulažete dok povećava dobitke i gubitke.

## Differences Futures & Options

Glavna razlika između futures i opcija je ta što je ugovor opcionalan za kupca: On može odlučiti da ga izvrši ili ne (obično će to učiniti samo ako će imati koristi od toga). Prodavac mora prodati ako kupac želi da iskoristi opciju.\
Međutim, kupac će plaćati neku naknadu prodavcu za otvaranje opcije (tako da prodavac, koji očigledno preuzima veći rizik, počinje da zarađuje neki novac).

### 1. **Obaveza vs. Pravo:**

* **Futures:** Kada kupujete ili prodajete futures ugovor, ulazite u **obavezujući sporazum** da kupite ili prodate imovinu po određenoj ceni na budući datum. I kupac i prodavac su **obavezni** da ispune ugovor na isteku (osim ako se ugovor ne zatvori pre toga).
* **Opcije:** Sa opcijama, imate **pravo, ali ne i obavezu**, da kupite (u slučaju **call opcije**) ili prodate (u slučaju **put opcije**) imovinu po određenoj ceni pre ili na određeni datum isteka. **Kupac** ima opciju da izvrši, dok je **prodavac** obavezan da ispuni trgovinu ako kupac odluči da iskoristi opciju.

### 2. **Rizik:**

* **Futures:** I kupac i prodavac preuzimaju **neograničen rizik** jer su obavezni da završe ugovor. Rizik je razlika između dogovorene cene i tržišne cene na datum isteka.
* **Opcije:** Rizik kupca je ograničen na **premiju** plaćenu za kupovinu opcije. Ako tržište ne ide u korist vlasnika opcije, jednostavno mogu da puste opciju da istekne. Međutim, **prodavac** (pisac) opcije ima neograničen rizik ako tržište značajno ide protiv njih.

### 3. **Trošak:**

* **Futures:** Nema unapred troška osim margine potrebne za održavanje pozicije, jer su i kupac i prodavac obavezni da završe trgovinu.
* **Opcije:** Kupac mora unapred platiti **premiju opcije** za pravo da izvrši opciju. Ova premija je u suštini trošak opcije.

### 4. **Potencijal za profit:**

* **Futures:** Profit ili gubitak se zasniva na razlici između tržišne cene na isteku i dogovorene cene u ugovoru.
* **Opcije:** Kupac zarađuje kada tržište ide povoljno iznad izvršne cene za više od plaćene premije. Prodavac zarađuje zadržavajući premiju ako opcija nije izvršena.

{{#include /banners/hacktricks-training.md}}
