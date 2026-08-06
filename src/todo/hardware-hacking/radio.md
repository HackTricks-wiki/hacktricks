# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)is 'n gratis digitale seinanaliseerder vir GNU/Linux en macOS, ontwerp om inligting uit onbekende radioseine te onttrek. Dit ondersteun 'n verskeidenheid SDR-toestelle deur SoapySDR, en laat verstelbare demodulasie van FSK-, PSK- en ASK-seine toe, kan analoogvideo dekodeer, bursty seine analiseer en na analoogstemkanale luister (alles in real time).<sup>[[1]](#references)</sup>

### Basiese konfigurasie

Nadat dit geïnstalleer is, is daar 'n paar dinge wat jy kan oorweeg om te konfigureer.\
In settings (die tweede tab-knoppie) kan jy die **SDR device** kies of **select a file** om te lees, asook watter frekwensie om te stem en die Sample rate (aanbeveel tot 2.56Msps as jou rekenaar dit ondersteun).

![SigDigger settings wat SDR-toestel-, invoerlêer-, frekwensie- en sample rate-opsies wys](<../../images/image (245).png>)

In die GUI behaviour word dit aanbeveel om 'n paar dinge te aktiveer as jou rekenaar dit ondersteun:

![SigDigger - Basiese konfigurasie: In die GUI behaviour word dit aanbeveel om 'n paar dinge te aktiveer as jou rekenaar dit ondersteun](<../../images/image (472).png>)

> [!TIP]
> As jy agterkom dat jou rekenaar niks vaslê nie, probeer om OpenGL te deaktiveer en die sample rate te verlaag.

### Gebruike

- Om bloot **'n gedeelte van 'n sein vas te lê en dit te analiseer**, hou die "Push to capture"-knoppie so lank as nodig ingedruk.

![Basiese konfigurasie - Gebruike: Om bloot 'n gedeelte van 'n sein vas te lê en dit te analiseer, hou die "Push to capture"-knoppie so lank as nodig ingedruk](<../../images/image (960).png>)

- Die **Tuner** van SigDigger help om **beter seine vas te lê** (maar dit kan dit ook verswak). Begin ideaal met 0 en hou aan om dit **groter te maak totdat** jy vind dat die **noise** wat ingevoer word **groter** is as die **verbetering van die sein** wat jy benodig.

![SigDigger-tunerbeheer aangepas om die vasgelêde radiosein te verbeter](<../../images/image (1099).png>)

### Sinkronisering met 'n radiokanaal

Met [**SigDigger** ](https://github.com/BatchDrake/SigDigger), sinkroniseer met die kanaal waarna jy wil luister, konfigureer die "Baseband audio preview"-opsie, konfigureer die bandwith om al die inligting wat gestuur word te kry, en stel dan die Tuner op die vlak net voordat die noise werklik begin toeneem:<sup>[[1]](#references)</sup>

![SigDigger-radiokanaal gesinkroniseer met baseband audio preview en bandwydte gekonfigureer](<../../images/image (585).png>)

## Interessante truuks

- Wanneer 'n toestel bursts van inligting stuur, gaan die **eerste gedeelte gewoonlik 'n preamble wees**, dus hoef jy jou **nie te bekommer** as jy **geen inligting** daarin **vind nie** of as daar **foute** daarin is nie.
- In inligtingsframes behoort jy gewoonlik **verskillende frames te vind wat goed met mekaar belyn is**:

![Sinkronisering met radiokanaal - Interessante truuks: In inligtingsframes behoort jy gewoonlik verskillende frames te vind wat goed met mekaar belyn is](<../../images/image (1076).png>)

![Sinkronisering met radiokanaal - Interessante truuks: In inligtingsframes behoort jy gewoonlik verskillende frames te vind wat goed met mekaar belyn is](<../../images/image (597).png>)

- **Nadat jy die bits herwin het, sal jy hulle moontlik op 'n manier moet verwerk**. Byvoorbeeld, in Manchester codification sal 'n op+af 'n 1 of 0 wees, en 'n af+op sal die ander een wees. Pare van 1'e en 0'e (oppe en affe) sal dus 'n werklike 1 of 'n werklike 0 wees.
- Selfs al gebruik 'n sein Manchester codification (dit is onmoontlik om meer as twee 0'e of 1'e in 'n ry te vind), kan jy **verskeie 1'e of 0'e saam in die preamble vind**!

### Ontdekking van modulasietipe met IQ

Daar is 3 maniere om inligting in seine te stoor: Deur die **amplitude**, **frekwensie** of **fase** te moduleer.\
As jy 'n sein nagaan, is daar verskillende maniere om te probeer uitvind wat gebruik word om inligting te stoor (vind meer maniere hieronder), maar 'n goeie manier is om die IQ-grafiek na te gaan.

![SigDigger IQ-grafiek wat gebruik word om te identifiseer of 'n sein amplitude-, frekwensie- of fasemodulasie gebruik](<../../images/image (788).png>)

- **Opsporing van AM**: As daar byvoorbeeld **2 sirkels** in die IQ-grafiek verskyn (waarskynlik een by 0 en die ander by 'n ander amplitude), kan dit beteken dat dit 'n AM-sein is. Dit is omdat die afstand tussen 0 en die sirkel in die IQ-grafiek die amplitude van die sein is, wat dit maklik maak om verskillende gebruikte amplitudes te visualiseer.
- **Opsporing van PM**: Soos in die vorige beeld, as jy klein sirkels vind wat nie met mekaar verband hou nie, beteken dit waarskynlik dat fasemodulasie gebruik word. Dit is omdat die hoek tussen die punt en 0,0 in die IQ-grafiek die fase van die sein is; dit beteken dus dat 4 verskillende fases gebruik word.
- Let daarop dat as die inligting versteek is in die feit dat 'n fase verander en nie in die fase self nie, jy nie verskillende fases duidelik onderskei sal sien nie.
- **Opsporing van FM**: IQ het nie 'n veld om frekwensies te identifiseer nie (afstand na die middel is amplitude en hoek is fase).\
Om FM te identifiseer, behoort jy dus **basies net 'n sirkel** in hierdie grafiek te sien.\
Verder word 'n verskillende frekwensie deur die IQ-grafiek voorgestel as 'n **versnellende spoed rondom die sirkel** (dus, wanneer die sein in SysDigger gekies word en die IQ-grafiek gevul word, kan 'n versnelling of verandering van rigting in die geskepte sirkel beteken dat dit FM is):

## AM-voorbeeld

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Ontdekking van AM

#### Kontrolering van die envelope

Wanneer jy AM-inligting met [**SigDigger** ](https://github.com/BatchDrake/SigDigger) nagaan en bloot na die **envelop** kyk, kan jy verskillende duidelike amplitudovlakke sien. Die gebruikte sein stuur pulses met inligting in AM; so lyk een pulse:<sup>[[1]](#references)</sup>

![SigDigger AM-seinenvelop met duidelike pulse-amplitudovlakke](<../../images/image (590).png>)

En so lyk 'n gedeelte van die simbool met die waveform:

![Ontdekking van AM - Kontrolering van die envelope: So lyk 'n gedeelte van die simbool met die waveform](<../../images/image (734).png>)

#### Kontrolering van die Histogram

Jy kan die **hele sein selekteer** waar die inligting geleë is, die **Amplitude**-modus en **Selection** kies, en op **Histogram** klik. Jy kan waarneem dat slegs 2 duidelike vlakke gevind word.

![SigDigger-amplitudehistogram wat twee duidelike vlakke vir die geselekteerde AM-sein wys](<../../images/image (264).png>)

As jy byvoorbeeld Frequency in plaas van Amplitude in hierdie AM-sein kies, vind jy net 1 frekwensie (dit is nie moontlik dat inligting wat in frekwensie gemoduleer is net 1 frekwensie gebruik nie).

![SigDigger-frekwensiehistogram vir die AM-sein wat een frekwensie wys](<../../images/image (732).png>)

As jy baie frekwensies vind, sal dit moontlik nie FM wees nie; die seingrekwensie is waarskynlik bloot weens die kanaal gewysig.

#### Met IQ

In hierdie voorbeeld kan jy sien dat daar 'n **groot sirkel** is, maar ook **baie punte in die middel**.

![Kontrolering van die Histogram - Met IQ: In hierdie voorbeeld kan jy sien dat daar 'n groot sirkel is, maar ook baie punte in die middel](<../../images/image (222).png>)

### Kry die simbooltempo

#### Met een simbool

Kies die kleinste simbool wat jy kan vind (sodat jy seker is dit is net 1) en kontroleer die "Selection freq". In hierdie geval sou dit 1.013kHz wees (dus 1kHz).

![Kry die simbooltempo - Met een simbool: Kies die kleinste simbool wat jy kan vind (sodat jy seker is dit is net 1) en kontroleer die "Selection freq". In hierdie geval sou dit 1.013kHz wees (dus 1kHz)](<../../images/image (78).png>)

#### Met 'n groep simbole

Jy kan ook die aantal simbole aandui wat jy gaan selekteer, waarna SigDigger die frekwensie van 1 simbool sal bereken (hoe meer simbole geselekteer word, hoe beter waarskynlik). In hierdie scenario het ek 10 simbole geselekteer en die "Selection freq" is 1.004 Khz:

![SigDigger-simbooltempo-berekening met 'n geselekteerde groep van tien simbole](<../../images/image (1008).png>)

### Kry bits

Nadat jy vasgestel het dat dit 'n **AM-gemoduleerde** sein is en die **simbooltempo** gevind het (en weet dat iets wat opgaan in hierdie geval 1 beteken en iets wat afgaan 0 beteken), is dit baie maklik om die **bits** wat in die sein geënkodeer is te **verkry**. Selekteer dus die sein met inligting, konfigureer die sampling en decision, en druk sample (maak seker dat **Amplitude** geselekteer is, die ontdekte **Symbol rate** gekonfigureer is en **Gadner clock recovery** geselekteer is):

![SigDigger Get Bits-paneel gekonfigureer vir AM-sampling, simbooltempo en Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** beteken dat, as jy voorheen intervalle geselekteer het om die simbooltempo te vind, daardie simbooltempo gebruik sal word.
- **Manual** beteken dat die aangeduide simbooltempo gebruik sal word.
- In **Fixed interval selection** dui jy die aantal intervalle aan wat geselekteer moet word, waarna dit die simbooltempo daaruit bereken.
- **Gadner clock recovery** is gewoonlik die beste opsie, maar jy moet steeds 'n benaderde simbooltempo aandui.

Wanneer jy sample druk, verskyn dit:

![Met 'n groep simbole - Kry bits: Dit verskyn wanneer jy sample druk](<../../images/image (644).png>)

Om SigDigger nou te laat verstaan **waar die reeks** van die vlak wat inligting dra is, moet jy op die **laer vlak** klik en die klik behou tot by die grootste vlak:

![SigDigger-vlakreeksseleksie vanaf die laer amplitudovlak tot by die boonste vlak](<../../images/image (439).png>)

As daar byvoorbeeld **4 verskillende amplitudovlakke** was, moes jy die **Bits per symbol op 2** gekonfigureer het en van die kleinste tot die grootste geselekteer het.

Deur uiteindelik die **Zoom** te **verhoog** en die **Row size** te **verander**, kan jy die bits sien (en jy kan alles selekteer en kopieer om al die bits te kry):

![Met 'n groep simbole - Kry bits: Deur uiteindelik die Zoom te verhoog en die Row size te verander, kan jy die bits sien (en jy kan alles selekteer en kopieer om al die bits te kry)](<../../images/image (276).png>)

As die sein meer as 1 bit per simbool het (byvoorbeeld 2), het SigDigger **geen manier om te weet watter simbool** 00, 01, 10 of 11 is nie. Dit sal dus verskillende **gryskale** gebruik om elkeen voor te stel (en as jy die bits kopieer, sal dit **getalle van 0 tot 3** gebruik; jy sal hulle moet verwerk).

Gebruik ook **codifications** soos **Manchester**, waar **op+af** **1 of 0** kan wees en **af+op** 'n 1 of 0 kan wees. In hierdie gevalle moet jy die verkrygde oppe (1'e) en affe (0'e) **verwerk** om die pare 01 of 10 met 0'e of 1'e te vervang.

## FM-voorbeeld

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Ontdekking van FM

#### Kontrolering van die frekwensies en waveform

Seinvoorbeeld wat inligting stuur wat in FM gemoduleer is:

![Ontdekking van FM - Kontrolering van die frekwensies en waveform: Seinvoorbeeld wat inligting stuur wat in FM gemoduleer is](<../../images/image (725).png>)

In die vorige beeld kan jy redelik goed waarneem dat **2 frekwensies gebruik word**, maar as jy die **waveform** **waarneem**, sal jy moontlik **nie die 2 verskillende frekwensies korrek kan identifiseer nie**:

![SigDigger FM-waveform waar die twee frekwensies moeilik direk onderskei kan word](<../../images/image (717).png>)

Dit is omdat ek die sein op albei frekwensies vasgelê het; daarom is die een ongeveer die negatiewe van die ander:

![SigDigger FM-opname wat die twee frekwensies as benaderde negatiewe van mekaar wys](<../../images/image (942).png>)

As die gesinkroniseerde frekwensie **nader aan een frekwensie as aan die ander** is, kan jy die 2 verskillende frekwensies maklik sien:

![Ontdekking van FM - Kontrolering van die frekwensies en waveform: As die gesinkroniseerde frekwensie nader aan een frekwensie as aan die ander is, kan jy die 2 verskillende frekwensies maklik sien](<../../images/image (422).png>)

![Ontdekking van FM - Kontrolering van die frekwensies en waveform: As die gesinkroniseerde frekwensie nader aan een frekwensie as aan die ander is, kan jy die 2 verskillende frekwensies maklik sien](<../../images/image (488).png>)

#### Kontrolering van die histogram

Deur die frekwensiehistogram van die sein met inligting na te gaan, kan jy maklik 2 verskillende seine sien:

![Kontrolering van die frekwensies en waveform - Kontrolering van die histogram: Deur die frekwensiehistogram van die sein met inligting na te gaan, kan jy maklik 2 verskillende seine sien](<../../images/image (871).png>)

As jy in hierdie geval die **Amplitude histogram** nagaan, sal jy **slegs een amplitude** vind, dus **kan dit nie AM wees nie** (as jy baie amplitudes vind, kan dit wees omdat die sein langs die kanaal krag verloor het):

![SigDigger-amplitudehistogram vir FM-sein wat 'n enkele amplitudovlak wys](<../../images/image (817).png>)

En dit sou die fasehistogram wees (wat dit baie duidelik maak dat die sein nie in fase gemoduleer is nie):

![Kontrolering van die frekwensies en waveform - Kontrolering van die histogram: Dit sou die fasehistogram wees, wat dit baie duidelik maak dat die sein nie in fase gemoduleer is nie](<../../images/image (996).png>)

#### Met IQ

IQ het nie 'n veld om frekwensies te identifiseer nie (afstand na die middel is amplitude en hoek is fase).\
Om FM te identifiseer, behoort jy dus **basies net 'n sirkel** in hierdie grafiek te sien.\
Verder word 'n verskillende frekwensie deur die IQ-grafiek voorgestel as 'n **versnellende spoed rondom die sirkel** (dus, wanneer die sein in SysDigger gekies word en die IQ-grafiek gevul word, kan 'n versnelling of verandering van rigting in die geskepte sirkel beteken dat dit FM is):

![SigDigger IQ-grafiek waar FM as veranderinge in versnelling rondom die sirkel verskyn](<../../images/image (81).png>)

### Kry die simbooltempo

Jy kan **dieselfde tegniek as die een in die AM-voorbeeld** gebruik om die simbooltempo te kry nadat jy die frekwensies gevind het wat simbole dra.

### Kry bits

Jy kan **dieselfde tegniek as die een in die AM-voorbeeld** gebruik om die bits te kry nadat jy **vasgestel het dat die sein in frekwensie gemoduleer is** en die **simbooltempo** gevind het.

## Verwysings

- [1] [SigDigger - Free digital signal analyzer for GNU/Linux and macOS](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
