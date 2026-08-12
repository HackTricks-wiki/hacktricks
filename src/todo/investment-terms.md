# Investicioni termini

{{#include ../banners/hacktricks-training.md}}

## Spot

Spot trgovanje podrazumeva razmenu imovine uz trenutnu isporuku. Limit nalog navodi količinu i ograničavajuću cenu; izvršava se samo kada tržište može da ispuni tu cenu ili povoljniju cenu. Market nalog, s druge strane, nastoji da se izvrši odmah po najboljim trenutno dostupnim cenama i može biti izložen klizanju cene.<sup>[[4]](#references)</sup>

Stop-limit nalog ima stop cenu koja aktivira limit nalog. Može ograničiti cenu izvršenja, ali ne garantuje izvršenje ako se tržište kreće kroz limit cenu.<sup>[[4]](#references)</sup>

## Fjučersi

Futures ugovor je standardizovani sporazum o kupovini ili prodaji određene robe ili finansijskog instrumenta na budući datum. Na primer, dve strane mogu da se dogovore o ceni od 70.000 USD za jedan bitcoin, uz poravnanje za šest meseci.<sup>[[1]](#references)</sup>

Ako je cena poravnanja 80.000 USD, long strana ostvaruje dobit, a short strana gubitak u odnosu na ugovorenu cenu od 70.000 USD. Ako je cena 60.000 USD, odnos je obrnut. Fjučersi kojima se stvarno trguje na berzi obračunavaju se po tržišnoj vrednosti i obično se zatvaraju ili prebacuju pre isteka, tako da je ovo pojednostavljena ilustracija.<sup>[[2]](#references)</sup>

Proizvođači i potrošači koriste fjučerse za zaštitu od cenovnog rizika; drugi učesnici ih koriste u potrazi za profitom ili za obezbeđivanje likvidnosti.<sup>[[1]](#references)</sup>

- **Long pozicija** generalno ostvaruje dobit kada cena ugovora raste.
- **Short pozicija** generalno ostvaruje dobit kada cena ugovora pada.<sup>[[2]](#references)</sup>

### Hedging pomoću fjučersa

Ako portfolio menadžer očekuje pad portfolija, može otvoriti short poziciju u dovoljno korelisanom futures ugovoru na berzanski indeks. Dobici na short hedging poziciji mogu nadoknaditi deo gubitaka portfolija; bazni rizik znači da nadoknada retko bude potpuno precizna. Bitcoin future bi zaštitio izloženost bitcoinu, ali ne i automatski portfolio akcija.

Ako zaštićeno tržište pada, short futures pozicija može ostvariti dobit dok holdings gube vrednost. Ako tržište raste, holdings mogu ostvariti dobit dok hedging pozicija gubi. Hedging smanjuje odabrani rizik, umesto da stvara garantovani profit.<sup>[[1]](#references)</sup>

### Perpetual fjučersi

Perpetual ugovori su derivati bez fiksnog datuma isteka. Crypto platforme za trgovanje obično koriste periodična funding plaćanja kako bi pomogle da njihova cena ostane blizu osnovne spot cene; uslovi se razlikuju u zavisnosti od platforme.<sup>[[3]](#references)</sup>

Dobit i gubitak se menjaju kako se menja mark cena. Promena cene od 1% proizvodi približno promenu od 1% nominalne vrednosti pozicije pre naknada i funding-a, ali leverage može učiniti da to bude mnogo veći procenat uplaćenog kolaterala.

### Fjučersi sa Leverage-om

**Leverage** omogućava traderu da kontroliše veću nominalnu poziciju uz manji depozit margine. Gubici nisu uvek ograničeni na početnu marginu: likvidacija, cenovni gap-ovi, naknade i pravila platforme mogu proizvesti dodatne gubitke.<sup>[[3]](#references)</sup>

Na primer, margina od 100 USD uz leverage od 50x kontroliše poziciju od 5.000 USD. Ako zanemarimo naknade, funding i mehanizme likvidacije, povoljno kretanje od 1% proizvodi dobit od 50 USD (50% početne margine), dok nepovoljno kretanje od 1% proizvodi gubitak od 50 USD. Nepovoljno kretanje od 2% odgovara iznosu od 100 USD, iako će platforma obično likvidirati poziciju pre nego što se cela margina iscrpi.

Leverage uvećava i dobitke i gubitke i omogućava likvidaciju nakon relativno malog nepovoljnog kretanja.

## Razlike između fjučersa i opcija

Kupac opcije dobija pravo, a ne obavezu, da izvrši opciju u skladu sa uslovima ugovora. Prodavac opcije ima odgovarajuću obavezu ako kupac izvrši opciju. Kupac plaća prodavcu premiju za to pravo.<sup>[[4]](#references)</sup>

### 1. **Obaveza naspram prava:**

* **Fjučersi:** Kada kupite ili prodate futures ugovor, sklapate **obavezujući sporazum** o kupovini ili prodaji imovine po određenoj ceni na budući datum. I kupac i prodavac su **obavezni** da ispune ugovor po isteku (osim ako se ugovor zatvori pre toga).
* **Opcije:** Kod opcija imate **pravo, ali ne i obavezu**, da kupite (u slučaju **call opcije**) ili prodate (u slučaju **put opcije**) imovinu po određenoj ceni pre određenog datuma isteka ili na taj datum. **Kupac** ima mogućnost da izvrši opciju, dok je **prodavac** obavezan da realizuje trgovinu ako kupac odluči da izvrši opciju.

### 2. **Rizik:**

* **Fjučersi:** Obe strane mogu pretrpeti značajne gubitke. Da li je gubitak matematički neograničen zavisi od pozicije i osnovne imovine: short pozicija može imati teoretski neograničen gubitak, dok long pozicija ne može izgubiti više od nominalne vrednosti ako osnovna imovina ne može pasti ispod nule.
* **Opcije:** Kupac koji ne prodaje drugu opciju obično rizikuje plaćenu premiju. Prodavac naked call opcije može se suočiti sa teoretski neograničenim gubitkom; druge strategije prodaje opcija imaju različite ograničene ili neograničene profile rizika.

### 3. **Trošak:**

* **Fjučersi:** Ne postoji početni trošak osim margine potrebne za držanje pozicije, pošto su i kupac i prodavac obavezni da završe trgovinu.
* **Opcije:** Kupac mora unapred da plati **premiju opcije** za pravo izvršenja opcije. Ova premija je u suštini trošak opcije.

### 4. **Potencijal profita:**

* **Fjučersi:** Profit ili gubitak zasniva se na razlici između tržišne cene po isteku i dogovorene cene u ugovoru.
* **Opcije:** Kupac ostvaruje profit kada se tržište povoljno pomeri iznad strike cene za više od plaćene premije. Prodavac ostvaruje profit zadržavanjem premije ako opcija nije izvršena.

## References

- [1] [CFTC - Ekonomska svrha futures tržišta](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Osnove futures tržišta](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Razumevanje rizika trgovanja virtuelnim valutama](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC rečnik - Opcija, premija i izvršenje](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../banners/hacktricks-training.md}}
