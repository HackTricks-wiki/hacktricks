# Beleggingsterme

{{#include ../banners/hacktricks-training.md}}

## Spot

Spot-handel ruil 'n bate vir onmiddellike lewering. 'n Limietorder spesifiseer die hoeveelheid en limietprys; dit word slegs uitgevoer wanneer die mark daardie prys of 'n beter prys kan bied. 'n Markorder poog daarenteen om vinnig uitgevoer te word teen die beste pryse wat dan beskikbaar is, en kan prysglyding ervaar.<sup>[[4]](#references)</sup>

'n Stop-limietorder het 'n stopprys wat 'n limietorder aktiveer. Dit kan die uitvoeringsprys beperk, maar waarborg nie uitvoering as die mark deur die limietprys beweeg nie.<sup>[[4]](#references)</sup>

## Termynkontrakte

'n Termynkontrak is 'n gestandaardiseerde ooreenkoms om 'n bepaalde kommoditeit of finansiële instrument op 'n toekomstige datum te koop of te verkoop. Twee partye kan byvoorbeeld op 'n prys van $70,000 vir een bitcoin ooreenkom, met vereffening oor ses maande.<sup>[[1]](#references)</sup>

As die vereffeningsprys $80,000 is, maak die lang kant wins en ly die kort kant 'n verlies relatief tot die kontrakprys van $70,000. As dit $60,000 is, word die rigting omgekeer. Werklike beursverhandelde termynkontrakte word teen markwaarde gewaardeer en gewoonlik voor verstryking gesluit of omgerol, dus is dit 'n vereenvoudigde illustrasie.<sup>[[2]](#references)</sup>

Produsente en verbruikers gebruik termynkontrakte om prysrisiko te verskans; ander deelnemers gebruik dit om wins te probeer maak of likiditeit te verskaf.<sup>[[1]](#references)</sup>

- 'n **Lang posisie** maak oor die algemeen wins wanneer die kontrakprys styg.
- 'n **Kort posisie** maak oor die algemeen wins wanneer die kontrakprys daal.<sup>[[2]](#references)</sup>

### Verskansing Met Termynkontrakte

As 'n fondsbestuurder verwag dat 'n portefeulje sal daal, kan hulle 'n voldoende gekorreleerde aandele-indeks-termynkontrak kort verkoop. Winste op die kort verskansing kan sommige portefeuljeverliese verreken; basisrisiko beteken dat die verrekening selde presies is. 'n Bitcoin-termynkontrak sal blootstelling aan bitcoin verskans, nie outomaties 'n aandeleportefeulje nie.

As die verskanste mark daal, kan die kort termynposisie wins maak terwyl die besittings waarde verloor. As dit styg, kan die besittings wins maak terwyl die verskansing verloor. Verskansing verminder 'n gekose risiko eerder as om 'n gewaarborgde wins te skep.<sup>[[1]](#references)</sup>

### Ewigdurende Termynkontrakte

Ewigdurende kontrakte is afgeleide instrumente sonder 'n vaste vervaldatum. Crypto-platforms gebruik algemeen periodieke befondsingsbetalings om hul prys naby die onderliggende spotprys te hou; terme verskil volgens platform.<sup>[[3]](#references)</sup>

Wins en verlies verander namate die merkprys beweeg. 'n Prysbeweging van 1% lewer ongeveer 'n beweging van 1% op die posisie se nominale waarde voor fooie en befondsing, maar hefboomwerking kan dit 'n veel groter persentasie van die gestorte kollateraal maak.

### Termynkontrakte met Hefboomwerking

**Hefboomwerking** stel 'n handelaar in staat om 'n groter nominale posisie met 'n kleiner margeverpligting te beheer. Verliese is nie altyd tot die aanvanklike marge beperk nie: likwidasie, gapings, fooie en platformreëls kan bykomende verliese veroorsaak.<sup>[[3]](#references)</sup>

Byvoorbeeld, $100 se marge teen 50x hefboomwerking beheer 'n posisie van $5,000. As fooie, befondsing en likwidas meganismes geïgnoreer word, lewer 'n gunstige beweging van 1% 'n wins van $50 (50% van die aanvanklike marge), terwyl 'n ongunstige beweging van 1% 'n verlies van $50 lewer. 'n Ongunstige beweging van 2% stem ooreen met $100, hoewel 'n platform die posisie normaalweg sal likwideer voordat die hele marge opgebruik is.

Hefboomwerking vergroot sowel winste as verliese en maak likwidasie ná 'n betreklik klein ongunstige beweging moontlik.

## Verskille Tussen Termynkontrakte en Opsies

'n Opsiekoper ontvang 'n reg, nie 'n verpligting nie, om ingevolge die kontrakvoorwaardes uit te oefen. Die opsieskrywer het die ooreenstemmende verpligting indien die koper uitoefen. Die koper betaal die skrywer 'n premie vir daardie reg.<sup>[[4]](#references)</sup>

### 1. **Verpligting teenoor Reg:**

* **Termynkontrakte:** Wanneer jy 'n termynkontrak koop of verkoop, tree jy 'n **bindende ooreenkoms** aan om 'n bate teen 'n spesifieke prys op 'n toekomstige datum te koop of te verkoop. Sowel die koper as die verkoper is **verplig** om die kontrak by verstryking na te kom (tensy die kontrak voor dan gesluit word).
* **Opsies:** Met opsies het jy die **reg, maar nie die verpligting nie**, om 'n bate teen 'n spesifieke prys voor of op 'n bepaalde vervaldatum te koop (in die geval van 'n **call-opsie**) of te verkoop (in die geval van 'n **put-opsie**). Die **koper** het die opsie om uit te oefen, terwyl die **verkoper** verplig is om die transaksie uit te voer indien die koper besluit om die opsie uit te oefen.

### 2. **Risiko:**

* **Termynkontrakte:** Albei kante kan aansienlike verliese ly. Of die verlies wiskundig onbeperk is, hang van die posisie en onderliggende bate af: 'n kort posisie kan 'n onbeperkte teoretiese verlies hê, terwyl 'n lang posisie nie meer as die nominale waarde kan verloor indien die onderliggende bate nie onder nul kan daal nie.
* **Opsies:** 'n Koper wat nie 'n ander opsie skryf nie, loop oor die algemeen die risiko van die betaalde premie. 'n Onbedekte call-skrywer kan 'n teoreties onbeperkte verlies ly; ander opsieskryfstrategieë het verskillende begrensde of onbeperkte risikoprofiele.

### 3. **Koste:**

* **Termynkontrakte:** Daar is geen voorafkoste buiten die marge wat vereis word om die posisie te hou nie, aangesien die koper en verkoper albei verplig is om die transaksie te voltooi.
* **Opsies:** Die koper moet vooraf 'n **opsiepremie** betaal vir die reg om die opsie uit te oefen. Hierdie premie is in wese die koste van die opsie.

### 4. **Winsmoontlikheid:**

* **Termynkontrakte:** Die wins of verlies is gebaseer op die verskil tussen die markprys by verstryking en die ooreengekome prys in die kontrak.
* **Opsies:** Die koper maak wins wanneer die mark gunstig verby die uitoefeningsprys beweeg met meer as die betaalde premie. Die verkoper maak wins deur die premie te behou indien die opsie nie uitgeoefen word nie.

## References

- [1] [CFTC - Die ekonomiese doel van termynmarkte](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Basiese beginsels van termynmarkte](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Verstaan die risiko's van virtuele-geldeenheidshandel](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC-woordelys - Opsie, premie en uitoefening](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../banners/hacktricks-training.md}}
