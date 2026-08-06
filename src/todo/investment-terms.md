# Beleggingsterme

{{#include ../banners/hacktricks-training.md}}

## Spot

Dit is die mees basiese manier om handel te dryf. Jy kan **die hoeveelheid van die bate en die prys aandui** waarteen jy wil koop of verkoop, en wanneer daardie prys bereik word, word die transaksie uitgevoer.

Gewoonlik kan jy ook die **huidige markprys** gebruik om die transaksie so vinnig moontlik teen die huidige prys uit te voer.

**Stop Loss - Limit**: Jy kan ook die hoeveelheid en die prys van die bates wat gekoop of verkoop moet word aandui, terwyl jy ook ’n laer prys aandui waarteen gekoop of verkoop moet word indien dit bereik word (om verliese te stop).

## Futures

’n Future is ’n kontrak waarin 2 partye ooreenkom om **iets in die toekoms teen ’n vaste prys te bekom**. Byvoorbeeld, om 1 bitcoin oor 6 maande teen $70.000 te verkoop.

As die waarde van bitcoin na 6 maande natuurlik $80.000 is, verloor die verkoper geld en verdien die koper dit. As die waarde van bitcoin oor 6 maande $60.000 is, gebeur die teenoorgestelde.

Dit is egter byvoorbeeld interessant vir besighede wat ’n produk vervaardig en die sekerheid nodig het dat hulle dit teen ’n prys sal kan verkoop wat die koste dek. Dit is ook nuttig vir besighede wat vaste pryse in die toekoms vir iets wil verseker, selfs al is dit hoër.

Op exchanges word dit egter gewoonlik gebruik om wins te probeer maak.

* Let daarop dat ’n "Long position" beteken dat iemand daarop wed dat ’n prys gaan styg
* Terwyl ’n "short position" beteken dat iemand daarop wed dat ’n prys gaan daal

### Hedging With Futures <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

As ’n fondsbestuurder bang is dat sekere aandele gaan daal, kan hy ’n short position op sommige bates, soos bitcoin- of S\&P 500-futureskontrakte, inneem. Dit sal soortgelyk wees aan die aankoop of besit van sekere bates en die skep van ’n kontrak om dit op ’n toekomstige tyd teen ’n hoër prys te verkoop.

Indien die prys daal, sal die fondsbestuurder wins maak omdat hy die bates teen ’n hoër prys sal verkoop. As die prys van die bates styg, sal die bestuurder nie daardie voordeel verdien nie, maar hy sal steeds sy bates behou.

### Perpetual Futures

**Dit is "futures" wat onbepaald sal voortduur** (sonder ’n einddatum vir die kontrak). Dit is baie algemeen om dit byvoorbeeld op crypto-exchanges te vind, waar jy futures kan betree en verlaat op grond van die prys van crypto.

Let daarop dat die wins en verlies in hierdie gevalle intyds kan plaasvind: as die prys met 1% styg, wen jy 1%; as die prys met 1% daal, verloor jy dit.

### Futures with Leverage

**Leverage** stel jou in staat om ’n groter posisie in die mark met ’n kleiner hoeveelheid geld te beheer. Dit stel jou basies in staat om met veel meer geld te "wed" as wat jy het, terwyl jy slegs die geld wat jy werklik het, waag.

Byvoorbeeld, as jy ’n future-posisie in BTC/USDT met $100 en 50x leverage open, beteken dit dat as die prys met 1% styg, jy 1x50 = 50% van jou aanvanklike belegging ($50) sou wen. Jy sal dus $150 hê.\
As die prys egter met 1% daal, sal jy 50% van jou fondse verloor ($59 in hierdie geval). En as die prys met 2% daal, sal jy jou hele weddenskap verloor (2x50 = 100%).

Leverage stel jou dus in staat om die hoeveelheid geld waarop jy wed, te beheer terwyl dit die winste en verliese verhoog.

## Verskille tussen Futures en Options

Die belangrikste verskil tussen futures en options is dat die kontrak vir die koper opsioneel is: Hy kan besluit om dit uit te oefen of nie (gewoonlik sal hy dit slegs doen indien hy daarby sal baat). Die verkoper moet verkoop indien die koper die option wil gebruik.\
Die koper sal egter ’n fooi aan die verkoper betaal om die option te open (dus begin die verkoper, wat blykbaar meer risiko neem, reeds geld verdien).

### 1. **Verpligting teenoor Reg:**

* **Futures:** Wanneer jy ’n futures-kontrak koop of verkoop, tree jy ’n **bindende ooreenkoms** aan om ’n bate teen ’n spesifieke prys op ’n toekomstige datum te koop of verkoop. Beide die koper en verkoper is **verplig** om die kontrak by verstryking na te kom (tensy die kontrak voor daardie tyd gesluit word).
* **Options:** Met options het jy die **reg, maar nie die verpligting nie**, om ’n bate teen ’n spesifieke prys voor of op ’n sekere vervaldatum te koop (in die geval van ’n **call option**) of te verkoop (in die geval van ’n **put option**). Die **koper** het die opsie om dit uit te oefen, terwyl die **verkoper** verplig is om die transaksie uit te voer indien die koper besluit om die option uit te oefen.

### 2. **Risiko:**

* **Futures:** Beide die koper en verkoper neem **onbeperkte risiko** aan omdat hulle verplig is om die kontrak te voltooi. Die risiko is die verskil tussen die ooreengekome prys en die markprys op die vervaldatum.
* **Options:** Die koper se risiko is beperk tot die **premie** wat betaal is om die option te koop. As die mark nie in die optionhouer se guns beweeg nie, kan hy eenvoudig die option laat verval. Die **verkoper** (skrywer) van die option het egter onbeperkte risiko indien die mark beduidend teen hom beweeg.

### 3. **Koste:**

* **Futures:** Daar is geen voorafkoste buiten die margin wat benodig word om die posisie te hou nie, aangesien die koper en verkoper albei verplig is om die transaksie te voltooi.
* **Options:** Die koper moet vooraf ’n **option-premie** betaal vir die reg om die option uit te oefen. Hierdie premie is basies die koste van die option.

### 4. **Winsmoontlikheid:**

* **Futures:** Die wins of verlies is gebaseer op die verskil tussen die markprys by verstryking en die ooreengekome prys in die kontrak.
* **Options:** Die koper maak wins wanneer die mark gunstig beweeg tot bo die strike price met meer as die betaalde premie. Die verkoper maak wins deur die premie te behou indien die option nie uitgeoefen word nie.

{{#include ../banners/hacktricks-training.md}}
