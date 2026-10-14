# Uslovi investiranja

{{#include ../../banners/hacktricks-training.md}}

## Spot

Spot trgovanje je razmena imovine uz trenutnu isporuku. Limit nalog određuje količinu i limit cenu; izvršava se samo kada tržište može da ispuni tu cenu ili povoljniju. Market nalog, nasuprot tome, nastoji da se izvrši odmah po najboljim tada dostupnim cenama i može doći do proklizavanja.<sup>[[4]](#references)</sup>

Stop-limit nalog ima stop cenu koja aktivira limit nalog. Može da ograniči cenu izvršenja, ali ne garantuje izvršenje ako se tržište pomeri izvan limita.<sup>[[4]](#references)</sup>

## Fjučersi

Fjučers ugovor je standardizovani sporazum o kupovini ili prodaji određene robe ili finansijskog instrumenta na budući datum. Na primer, dve strane mogu da se dogovore o ceni od 70.000 $ za jedan bitcoin, uz poravnanje za šest meseci.<sup>[[1]](#references)</sup>

Ako je cena poravnanja 80.000 $, duga pozicija ostvaruje dobit, a kratka gubitak u odnosu na ugovorenu cenu od 70.000 $. Ako je cena 60.000 $, smer se obrće. Fjučersima kojima se trguje na berzi obračunava se dobit i gubitak prema tržišnoj vrednosti i obično se zatvaraju ili prenose na sledeći ugovor pre isteka, pa je ovo pojednostavljen primer.<sup>[[2]](#references)</sup>

Proizvođači i potrošači koriste fjučerse za zaštitu od rizika promene cena; drugi učesnici ih koriste u potrazi za profitom ili radi obezbeđivanja likvidnosti.<sup>[[1]](#references)</sup>

- **Duga pozicija** uglavnom ostvaruje dobit kada cena ugovora raste.
- **Kratka pozicija** uglavnom ostvaruje dobit kada cena ugovora pada.<sup>[[2]](#references)</sup>

### Zaštita od rizika pomoću fjučersa

Ako menadžer fonda očekuje pad vrednosti portfolija, mogao bi da zauzme kratku poziciju u fjučers ugovoru na berzanski indeks koji je dovoljno korelisan sa portfoliom. Dobit od kratke zaštitne pozicije može da nadoknadi deo gubitaka portfolija; rizik osnovice znači da nadoknada retko bude tačna. Bitcoin fjučers bi štitio izloženost bitcoinu, ali ne bi automatski štitio portfolio akcija.

Ako zaštićeno tržište padne, kratka fjučers pozicija može da ostvari dobit dok ulaganja gube vrednost. Ako tržište poraste, ulaganja mogu da ostvare dobit dok zaštitna pozicija gubi vrednost. Zaštita smanjuje odabrane rizike, ali ne garantuje profit.<sup>[[1]](#references)</sup>

### Perpetual fjučersi

Perpetual ugovori su derivati bez fiksnog datuma isteka. Kripto-platforme često koriste periodične funding isplate kako bi pomogle da njihova cena ostane blizu osnovne spot cene; uslovi se razlikuju od platforme do platforme.<sup>[[3]](#references)</sup>

Dobit i gubitak se menjaju kako se menja mark cena. Promena cene od 1% dovodi do približno 1% promene nominalne vrednosti pozicije, pre naknada i funding isplata, ali poluga može učiniti da to bude znatno veći procenat položene marže.

### Fjučersi sa polugom

**Poluga** omogućava trgovcu da kontroliše veću nominalnu poziciju uz manji depozit marže. Gubici nisu uvek ograničeni na početnu maržu: likvidacija, nagli skokovi cena, naknade i pravila platforme mogu dovesti do dodatnih gubitaka.<sup>[[3]](#references)</sup>

Na primer, marža od 100 $ uz polugu 50x kontroliše poziciju od 5.000 $. Zanemarujući naknade, funding isplate i mehanizme likvidacije, povoljna promena od 1% donosi dobit od 50 $ (50% početne marže), dok nepovoljna promena od 1% donosi gubitak od 50 $. Nepovoljna promena od 2% odgovara iznosu od 100 $, mada će platforma obično likvidirati poziciju pre nego što se potroši celokupna marža.

Poluga uvećava i dobitke i gubitke i omogućava likvidaciju nakon relativno male nepovoljne promene cene.

## Razlike između fjučersa i opcija

Kupac opcije dobija pravo, ali ne i obavezu, da je izvrši pod uslovima ugovora. Izdavalac opcije ima odgovarajuću obavezu ako kupac odluči da je izvrši. Kupac za to pravo plaća izdavaocu premiju.<sup>[[4]](#references)</sup>

### 1. **Obaveza naspram prava:**

* **Fjučersi:** Kada kupite ili prodate fjučers ugovor, sklapate **obavezujući sporazum** o kupovini ili prodaji imovine po određenoj ceni na budući datum. I kupac i prodavac imaju **obavezu** da ispune ugovor po isteku (osim ako se ugovor ne zatvori pre toga).
* **Opcije:** Kod opcija imate **pravo, ali ne i obavezu**, da kupite (u slučaju **call opcije**) ili prodate (u slučaju **put opcije**) imovinu po određenoj ceni pre određenog datuma isteka ili na taj datum. **Kupac** ima mogućnost da izvrši opciju, dok je **prodavac** dužan da ispuni transakciju ako kupac odluči da je izvrši.

### 2. **Rizik:**

* **Fjučersi:** Obe strane mogu da pretrpe znatne gubitke. Da li je gubitak matematički neograničen zavisi od pozicije i osnovne imovine: kratka pozicija može imati teorijski neograničen gubitak, dok duga pozicija ne može izgubiti više od nominalne vrednosti ako vrednost osnovne imovine ne može pasti ispod nule.
* **Opcije:** Kupac koji ne izdaje neku drugu opciju uglavnom rizikuje samo plaćenu premiju. Izdavalac nepokrivene call opcije može se suočiti s teorijski neograničenim gubitkom; druge strategije izdavanja opcija imaju različite ograničene ili neograničene profile rizika.

### 3. **Trošak:**

* **Fjučersi:** Nema početnog troška osim marže potrebne za držanje pozicije, jer su i kupac i prodavac dužni da izvrše transakciju.
* **Opcije:** Kupac mora unapred da plati **premiju opcije** za pravo da je izvrši. Ta premija je u suštini cena opcije.

### 4. **Potencijalna dobit:**

* **Fjučersi:** Dobit ili gubitak zasniva se na razlici između tržišne cene po isteku i ugovorene cene.
* **Opcije:** Kupac ostvaruje dobit kada se tržište pomeri u povoljnom smeru preko izvršne cene za iznos veći od plaćene premije. Prodavac ostvaruje dobit zadržavanjem premije ako se opcija ne izvrši.

## References

- [1] [CFTC - Ekonomska svrha fjučers tržišta](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Osnove fjučers tržišta](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Razumevanje rizika trgovanja virtuelnim valutama](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC rečnik - Opcija, premija i izvršenje](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
