# Beleggingsterme

{{#include ../../banners/hacktricks-training.md}}

## Spot

Spot-handel ruil ’n bate vir onmiddellike aflewering. ’n Limietorder spesifiseer die hoeveelheid en limietprys; dit word slegs uitgevoer wanneer die mark daardie prys of ’n beter een kan bied. ’n Markorder poog eerder om vinnig uitgevoer te word teen die beste pryse wat dan beskikbaar is, en kan glip ervaar.<sup>[[4]](#references)</sup>

’n Stoplimietorder het ’n stopprys wat ’n limietorder aktiveer. Dit kan die uitvoeringsprys beperk, maar waarborg nie uitvoering as die mark deur die limiet beweeg nie.<sup>[[4]](#references)</sup>

## Termynkontrakte

’n Termynkontrak is ’n gestandaardiseerde ooreenkoms om ’n bepaalde kommoditeit of finansiële instrument op ’n toekomstige datum te koop of te verkoop. Twee partye kan byvoorbeeld ooreenkom op ’n prys van $70,000 vir een bitcoin, met vereffening oor ses maande.<sup>[[1]](#references)</sup>

As die vereffeningsprys $80,000 is, maak die lang kant wins en die kort kant verlies in verhouding tot die kontrakprys van $70,000. As dit $60,000 is, is dit andersom. Werklike beursverhandelde termynkontrakte word daagliks teen markwaarde herbereken en word gewoonlik voor verstryking gesluit of oorgedra; dit is dus ’n vereenvoudigde voorbeeld.<sup>[[2]](#references)</sup>

Produsente en verbruikers gebruik termynkontrakte om prysrisiko te verskans; ander deelnemers gebruik dit om wins te probeer maak of likiditeit te verskaf.<sup>[[1]](#references)</sup>

- ’n **Lang posisie** maak oor die algemeen wins wanneer die kontrakprys styg.
- ’n **Kort posisie** maak oor die algemeen wins wanneer die kontrakprys daal.<sup>[[2]](#references)</sup>

### Verskansing met termynkontrakte

As ’n fondsbestuurder verwag dat ’n portefeulje sal daal, kan hulle ’n voldoende gekorreleerde aandele-indekstermynkontrak kort verkoop. Winste op die kort verskansing kan sommige portefeuljeverliese vergoed; basisrisiko beteken dat die verrekening selde presies is. ’n Bitcoin-termynkontrak sal blootstelling aan bitcoin verskans, nie outomaties ’n aandeleportefeulje nie.

As die verskanste mark daal, kan die kort termynposisie wins maak terwyl die besittings waarde verloor. As dit styg, kan die besittings waarde toeneem terwyl die verskansing verlies maak. Verskansing verminder bepaalde risiko’s eerder as om ’n gewaarborgde wins te lewer.<sup>[[1]](#references)</sup>

### Ewigdurende termynkontrakte

Ewigdurende kontrakte is afgeleide instrumente sonder ’n vaste vervaldatum. Kripto-platforms gebruik gewoonlik periodieke befondsingsbetalings om hul prys naby die onderliggende spotprys te hou; die bepalings verskil van platform tot platform.<sup>[[3]](#references)</sup>

Wins en verlies verander namate die merkprys beweeg. ’n Prysbeweging van 1% lewer ongeveer ’n beweging van 1% in die posisie se nominale waarde op, voor fooie en befondsing, maar hefboom kan dit ’n veel groter persentasie van die gedeponeerde kollateraal maak.

### Termynkontrakte met hefboom

**Hefboom** laat ’n handelaar toe om ’n groter nominale posisie te beheer met ’n kleiner margindeposito. Verliese is nie altyd beperk tot die aanvanklike marge nie: likwidasie, prysgapings, fooie en platformreëls kan bykomende verliese veroorsaak.<sup>[[3]](#references)</sup>

Byvoorbeeld, $100 se marge teen 50x-hefboom beheer ’n posisie van $5,000. As fooie, befondsing en likwidasie-meganismes buite rekening gelaat word, lewer ’n gunstige beweging van 1% ’n wins van $50 op (50% van die aanvanklike marge), terwyl ’n ongunstige beweging van 1% ’n verlies van $50 oplewer. ’n Ongunstige beweging van 2% stem ooreen met $100, hoewel ’n platform die posisie gewoonlik sal likwideer voordat die hele marge uitgeput is.

Hefboom vergroot sowel winste as verliese en maak likwidasie moontlik ná ’n betreklik klein ongunstige beweging.

## Verskille tussen termynkontrakte en opsies

’n Opsiekoper verkry ’n reg, nie ’n verpligting nie, om volgens die kontrakvoorwaardes uit te oefen. Die opsieskrywer het die ooreenstemmende verpligting as die koper die opsie uitoefen. Die koper betaal die skrywer ’n premie vir dié reg.<sup>[[4]](#references)</sup>

### 1. **Verpligting teenoor reg:**

* **Termynkontrakte:** Wanneer jy ’n termynkontrak koop of verkoop, sluit jy ’n **bindende ooreenkoms** aan om ’n bate teen ’n bepaalde prys op ’n toekomstige datum te koop of te verkoop. Beide die koper en die verkoper is **verplig** om die kontrak by verstryking na te kom (tensy die kontrak voor dan gesluit word).
* **Opsies:** Met opsies het jy die **reg, maar nie die verpligting nie**, om ’n bate teen ’n bepaalde prys voor of op ’n sekere vervaldatum te koop (in die geval van ’n **koopopsie**) of te verkoop (in die geval van ’n **verkoopopsie**). Die **koper** kan besluit om uit te oefen, terwyl die **verkoper** verplig is om die transaksie na te kom as die koper besluit om die opsie uit te oefen.

### 2. **Risiko:**

* **Termynkontrakte:** Beide kante kan aansienlike verliese ly. Of verlies wiskundig onbeperk is, hang af van die posisie en onderliggende bate: ’n kort posisie kan ’n teoreties onbeperkte verlies hê, terwyl ’n lang posisie nie meer as die nominale waarde kan verloor as die onderliggende bate nie onder nul kan daal nie.
* **Opsies:** ’n Koper wat nie ’n ander opsie skryf nie, loop gewoonlik die risiko om die betaalde premie te verloor. ’n Ongedekte koopopsieskrywer kan ’n teoreties onbeperkte verlies ly; ander opsiestrategieë het verskillende beperkte of onbeperkte risikoprofiele.

### 3. **Koste:**

* **Termynkontrakte:** Daar is geen voorafkoste buiten die marge wat nodig is om die posisie te hou nie, aangesien die koper en verkoper albei verplig is om die transaksie af te handel.
* **Opsies:** Die koper moet vooraf ’n **opsiepremie** betaal vir die reg om die opsie uit te oefen. Hierdie premie is in wese die koste van die opsie.

### 4. **Winsmoontlikheid:**

* **Termynkontrakte:** Die wins of verlies is gebaseer op die verskil tussen die markprys by verstryking en die ooreengekome prys in die kontrak.
* **Opsies:** Die koper maak wins wanneer die mark gunstig beweeg tot verder as die uitoefeningsprys met meer as die betaalde premie. Die verkoper maak wins deur die premie te behou as die opsie nie uitgeoefen word nie.

## References

- [1] [CFTC - Die ekonomiese doel van termynmarkte](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Basiese beginsels van termynmarkte](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Verstaan die risiko’s van handel in virtuele geldeenhede](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC-woordelys - Opsie, premie en uitoefening](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
