# Beleggingsterme

{{#include ../../banners/hacktricks-training.md}}

## Spot

Spotverhandeling ruil ’n bate vir onmiddellike lewering. ’n Limietorder spesifiseer die hoeveelheid en limietprys; dit word slegs uitgevoer wanneer die mark daardie prys of ’n beter een kan bied. ’n Markorder streef eerder na onmiddellike uitvoering teen die beste pryse wat op daardie oomblik beskikbaar is, en kan prysglyding ondervind.<sup>[[4]](#references)</sup>

’n Stop-limietorder het ’n stopprys wat ’n limietorder aktiveer. Dit kan die uitvoeringsprys beperk, maar waarborg nie uitvoering as die mark deur die limiet beweeg nie.<sup>[[4]](#references)</sup>

## Termynkontrakte

’n Termynkontrak is ’n gestandaardiseerde ooreenkoms om ’n bepaalde kommoditeit of finansiële instrument op ’n toekomstige datum te koop of te verkoop. Twee partye kan byvoorbeeld ooreenkom op ’n prys van $70,000 vir een bitcoin met vereffening oor ses maande.<sup>[[1]](#references)</sup>

As die vereffeningsprys $80,000 is, maak die lang posisie wins en die kort posisie verlies relatief tot die kontrakprys van $70,000. As dit $60,000 is, is die situasie omgekeerd. Werklike beursverhandelde termynkontrakte word teen markwaarde aangepas en gewoonlik voor verstryking gesluit of oorgedra; dit is dus ’n vereenvoudigde voorbeeld.<sup>[[2]](#references)</sup>

Produsente en verbruikers gebruik termynkontrakte om prysrisiko te verskans; ander deelnemers gebruik dit om wins na te streef of likiditeit te verskaf.<sup>[[1]](#references)</sup>

- ’n **Lang posisie** maak oor die algemeen wins wanneer die kontrakprys styg.
- ’n **Kort posisie** maak oor die algemeen wins wanneer die kontrakprys daal.<sup>[[2]](#references)</sup>

### Verskansing Met Termynkontrakte

As ’n fondsbestuurder verwag dat ’n portefeulje gaan daal, kan hulle ’n voldoende gekorreleerde termynkontrak op ’n aandele-indeks kort verkoop. Winste op die kort verskansing kan sommige portefeuljeverliese verreken; basisrisiko beteken dat die verrekening selde presies is. ’n Bitcoin-termynkontrak sal bitcoin-blootstelling verskans, nie vanself ’n aandeleportefeulje nie.

As die verskanste mark daal, kan die kort termynposisie wins maak terwyl die beleggings in waarde daal. As dit styg, kan die beleggings in waarde toeneem terwyl die verskansing verlies maak. Verskansing verminder bepaalde risiko’s eerder as om ’n gewaarborgde wins te skep.<sup>[[1]](#references)</sup>

### Perpetuele Termynkontrakte

Perpetuele kontrakte is afgeleide instrumente sonder ’n vaste vervaldatum. Kripto-handelsplatforms gebruik gewoonlik periodieke befondsingsbetalings om hul prys naby die onderliggende spotprys te hou; die bepalings verskil tussen platforms.<sup>[[3]](#references)</sup>

Vir toetse op misbruik van befondsingskoerse in on-chain perpetuele protokolle, sien [Uitbuiting van Perpetuele Befondsingskoerse](perpetual-funding-rate-exploitation.md).

Wins en verlies verander namate die markprys beweeg. ’n Prysbeweging van 1% lei tot ongeveer ’n beweging van 1% in die nominale waarde van die posisie, voor fooie en befondsing, maar hefboomwerking kan dit ’n veel groter persentasie van die gedeponeerde kollateraal maak.

### Termynkontrakte met Hefboomwerking

**Hefboomwerking** stel ’n handelaar in staat om ’n groter nominale posisie met ’n kleiner margindeposito te beheer. Verliese is nie altyd tot die aanvanklike marge beperk nie: likwidasie, prysgapings, fooie en platformreëls kan tot bykomende verliese lei.<sup>[[3]](#references)</sup>

Byvoorbeeld, $100 se marge teen 50x hefboomwerking beheer ’n posisie van $5,000. As fooie, befondsing en likwidasie-meganismes buite rekening gelaat word, lewer ’n gunstige beweging van 1% ’n wins van $50 (50% van die aanvanklike marge), terwyl ’n ongunstige beweging van 1% ’n verlies van $50 lewer. ’n Ongunstige beweging van 2% kom ooreen met $100, hoewel ’n platform die posisie normaalweg sal likwideer voordat al die marge opgebruik is.

Hefboomwerking vergroot sowel winste as verliese en maak likwidasie moontlik ná ’n betreklik klein ongunstige beweging.

## Verskille Tussen Termynkontrakte en Opsies

’n Opsiekoper ontvang ’n reg, nie ’n verpligting nie, om volgens die kontrakvoorwaardes uit te oefen. Die opsieskrywer het die ooreenstemmende verpligting as die koper die opsie uitoefen. Die koper betaal die skrywer ’n premie vir daardie reg.<sup>[[4]](#references)</sup>

### 1. **Verpligting teenoor Reg:**

* **Termynkontrakte:** Wanneer jy ’n termynkontrak koop of verkoop, sluit jy ’n **bindende ooreenkoms** aan om ’n bate op ’n toekomstige datum teen ’n spesifieke prys te koop of te verkoop. Sowel die koper as die verkoper is **verplig** om die kontrak by verstryking na te kom (tensy die kontrak voor dan gesluit word).
* **Opsies:** Met opsies het jy die **reg, maar nie die verpligting nie**, om ’n bate teen ’n spesifieke prys voor of op ’n bepaalde vervaldatum te koop (in die geval van ’n **koopopsie**) of te verkoop (in die geval van ’n **verkoopopsie**). Die **koper** kan kies om uit te oefen, terwyl die **verkoper** verplig is om die transaksie na te kom as die koper besluit om die opsie uit te oefen.

### 2. **Risiko:**

* **Termynkontrakte:** Albei kante kan aansienlike verliese ly. Of die verlies wiskundig onbeperk is, hang van die posisie en onderliggende bate af: ’n kort posisie kan ’n teoreties onbeperkte verlies hê, terwyl ’n lang posisie nie meer as die nominale waarde kan verloor as die onderliggende bate nie onder nul kan daal nie.
* **Opsies:** ’n Koper wat nie ’n ander opsie skryf nie, waag gewoonlik die premie wat betaal is. ’n Onverskanste skrywer van ’n koopopsie kan ’n teoreties onbeperkte verlies ly; ander strategieë om opsies te skryf, het verskillende beperkte of onbeperkte risikoprofiele.

### 3. **Koste:**

* **Termynkontrakte:** Daar is geen voorafkoste buiten die marge wat nodig is om die posisie te hou nie, aangesien die koper en verkoper albei verplig is om die transaksie af te handel.
* **Opsies:** Die koper moet vooraf ’n **opsiepremie** betaal vir die reg om die opsie uit te oefen. Hierdie premie is in wese die koste van die opsie.

### 4. **Winsmoontlikheid:**

* **Termynkontrakte:** Die wins of verlies is gebaseer op die verskil tussen die markprys by verstryking en die ooreengekome prys in die kontrak.
* **Opsies:** Die koper maak wins wanneer die mark gunstig beweeg tot verby die uitoefenprys met meer as die betaalde premie. Die verkoper maak wins deur die premie te behou as die opsie nie uitgeoefen word nie.

## References

- [1] [CFTC - Die ekonomiese doel van termynmarkte](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Grondbeginsels van termynmarkte](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Verstaan die risiko’s van virtuele-valutaverhandeling](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC Glossary - Opsie, premie en uitoefening](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
