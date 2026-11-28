# Investicioni pojmovi

{{#include ../../banners/hacktricks-training.md}}

## Spot

Spot trgovanje podrazumeva razmenu imovine uz trenutnu isporuku. Limit nalog određuje količinu i limit cenu; izvršava se samo kada tržište može da ponudi tu cenu ili bolju. Market nalog, s druge strane, teži brzom izvršenju po najboljim trenutno dostupnim cenama i može dovesti do klizanja cene.<sup>[[4]](#references)</sup>

Stop-limit nalog ima stop cenu koja aktivira limit nalog. Može da ograniči cenu izvršenja, ali ne garantuje izvršenje ako se tržište pomeri izvan limita.<sup>[[4]](#references)</sup>

## Fjučersi

Fjučers ugovor je standardizovani sporazum o kupovini ili prodaji određene robe ili finansijskog instrumenta na budući datum. Na primer, dve strane mogu da se dogovore o ceni od $70,000 za jedan bitcoin, uz poravnanje za šest meseci.<sup>[[1]](#references)</sup>

Ako je cena poravnanja $80,000, long strana ostvaruje dobit, a short strana gubitak u odnosu na ugovorenu cenu od $70,000. Ako je cena $60,000, ishod je obrnut. Fjučersi kojima se trguje na berzi svakodnevno se obično vrednuju po tržišnoj vrednosti i najčešće zatvaraju ili prenose na novi ugovor pre isteka, pa je ovo pojednostavljen primer.<sup>[[2]](#references)</sup>

Proizvođači i potrošači koriste fjučerse da bi se zaštitili od cenovnog rizika; drugi učesnici ih koriste u potrazi za profitom ili radi obezbeđivanja likvidnosti.<sup>[[1]](#references)</sup>

- **Long pozicija** uglavnom donosi dobit kada cena ugovora raste.
- **Short pozicija** uglavnom donosi dobit kada cena ugovora pada.<sup>[[2]](#references)</sup>

### Zaštita od rizika pomoću fjučersa

Ako menadžer fonda očekuje pad vrednosti portfolija, mogao bi da zauzme short poziciju u fjučers ugovoru na berzanski indeks koji je dovoljno korelisan s portfoliom. Dobici od short hedža mogu da nadoknade deo gubitaka portfolija; bazni rizik znači da je ta nadoknada retko potpuna. Bitcoin fjučers bi štitio izloženost bitcoinu, a ne automatski i portfolio akcija.

Ako zaštićeno tržište padne, short fjučers pozicija može dobiti na vrednosti dok vrednost imovine u portfoliju opada. Ako tržište poraste, vrednost imovine može porasti, dok hedž gubi na vrednosti. Hedžing smanjuje odabrani rizik, ali ne stvara garantovan profit.<sup>[[1]](#references)</sup>

### Perpetual fjučersi

Perpetual ugovori su derivati bez fiksnog datuma isteka. Kripto platforme obično koriste periodične uplate finansiranja kako bi njihova cena ostala blizu spot cene osnovne imovine; uslovi se razlikuju od platforme do platforme.<sup>[[3]](#references)</sup>

Za testiranje zloupotrebe stope finansiranja u on-chain perpetual protokolima, pogledajte [Eksploatacija stope finansiranja perpetual ugovora](perpetual-funding-rate-exploitation.md).

Dobit i gubitak se menjaju kako se menja mark cena. Promena cene od 1% dovodi do približno 1% promene nominalne vrednosti pozicije, pre naknada i finansiranja, ali poluga može da učini tu promenu znatno većim procentom uplaćenog kolaterala.

### Fjučersi uz polugu

**Poluga** omogućava trejderu da kontroliše veću nominalnu poziciju uz manji depozit margine. Gubici nisu uvek ograničeni na početnu marginu: likvidacija, nagli skokovi cena, naknade i pravila platforme mogu dovesti do dodatnih gubitaka.<sup>[[3]](#references)</sup>

Na primer, margina od $100 uz polugu 50x kontroliše poziciju od $5,000. Ako zanemarimo naknade, finansiranje i mehaniku likvidacije, povoljno kretanje od 1% donosi dobit od $50 (50% početne margine), dok nepovoljno kretanje od 1% donosi gubitak od $50. Nepovoljno kretanje od 2% odgovara gubitku od $100, mada će platforma obično likvidirati poziciju pre nego što se potroši cela margina.

Poluga uvećava i dobitke i gubitke i omogućava likvidaciju nakon relativno malog nepovoljnog pomeranja cene.

## Razlike između fjučersa i opcija

Kupac opcije stiče pravo, ali ne i obavezu, da izvrši ugovor pod njegovim uslovima. Izdavalac opcije ima odgovarajuću obavezu ako kupac odluči da je izvrši. Kupac plaća izdavaocu premiju za to pravo.<sup>[[4]](#references)</sup>

### 1. **Obaveza naspram prava:**

* **Fjučersi:** Kada kupite ili prodate fjučers ugovor, sklapate **obavezujući sporazum** o kupovini ili prodaji imovine po određenoj ceni na budući datum. I kupac i prodavac su **obavezni** da ispune ugovor na dan isteka (osim ako se ugovor ne zatvori pre toga).
* **Opcije:** Kod opcija imate **pravo, ali ne i obavezu**, da kupite (u slučaju **call opcije**) ili prodate (u slučaju **put opcije**) imovinu po određenoj ceni pre ili na određeni datum isteka. **Kupac** ima mogućnost da izvrši opciju, dok je **prodavac** obavezan da izvrši trgovinu ako kupac odluči da iskoristi opciju.

### 2. **Rizik:**

* **Fjučersi:** Obe strane mogu pretrpeti znatne gubitke. Da li je gubitak matematički neograničen zavisi od pozicije i osnovne imovine: short pozicija može imati teorijski neograničen gubitak, dok long pozicija ne može izgubiti više od nominalne vrednosti ako vrednost osnovne imovine ne može pasti ispod nule.
* **Opcije:** Kupac koji ne izdaje drugu opciju uglavnom rizikuje premiju koju je platio. Izdavalac nepokrivene call opcije može pretrpeti teorijski neograničen gubitak; druge strategije izdavanja opcija imaju različite ograničene ili neograničene profile rizika.

### 3. **Cena:**

* **Fjučersi:** Nema početnog troška osim margine potrebne za držanje pozicije, jer su i kupac i prodavac obavezni da realizuju trgovinu.
* **Opcije:** Kupac mora unapred da plati **premiju opcije** za pravo da je izvrši. Ta premija je u suštini cena opcije.

### 4. **Potencijalna dobit:**

* **Fjučersi:** Dobit ili gubitak zavise od razlike između tržišne cene na dan isteka i ugovorene cene.
* **Opcije:** Kupac ostvaruje dobit kada se tržište povoljno pomeri iznad izvršne cene za više od plaćene premije. Prodavac ostvaruje dobit zadržavanjem premije ako se opcija ne izvrši.

## References

- [1] [CFTC - Ekonomska svrha fjučers tržišta](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Osnove fjučers tržišta](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Razumevanje rizika trgovanja virtuelnim valutama](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC rečnik - Opcija, premija i izvršenje](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
