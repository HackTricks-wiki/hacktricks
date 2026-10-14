# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) is ’n gratis digitale-seinontleder vir GNU/Linux en macOS, ontwerp om inligting uit onbekende radioseine te onttrek. Dit ondersteun SDR-toestelle deur SoapySDR en bied intydse demodulasie- en ontledingsnutsgoed vir FSK, PSK, ASK, analoogvideo, burst-seine en analoogstemkanale.<sup>[[1]](#references)</sup>

### Basiese konfigurasie

Nadat jy dit geïnstalleer het, is daar ’n paar dinge wat jy kan oorweeg om te konfigureer.\
Kies in settings (die tweede oortjieknoppie) ’n **SDR-toestel** of ’n invoerlêer, die frekwensie waarop jy wil instel, en die sample rate. ’n Tempo van tot 2.56 Msps kan prakties wees as die gasheer dit ondersteun.

![SigDigger-instellings met opsies vir SDR-toestel, invoerlêer, frekwensie en sample rate](<../../images/image (245).png>)

In die GUI-gedrag word dit aanbeveel om ’n paar dinge te aktiveer as jou rekenaar dit ondersteun:

![SigDigger - Basiese konfigurasie: In die GUI-gedrag word dit aanbeveel om ’n paar dinge te aktiveer as jou rekenaar dit ondersteun](<../../images/image (472).png>)

> [!TIP]
> As jy agterkom dat jou rekenaar niks vasvang nie, probeer om OpenGL te deaktiveer en die sample rate te verlaag.

### Gebruike

- Om **’n sein vir ’n rukkie vas te vang en te ontleed**, hou die knoppie "Push to capture" ingedruk so lank as wat nodig is.

![Basiese konfigurasie - Gebruike: Om ’n sein vir ’n rukkie vas te vang en te ontleed, hou die knoppie "Push to capture" ingedruk so lank as wat nodig is](<../../images/image (960).png>)

- Die **Tuner** van SigDigger help om **seine beter vas te vang** (maar kan dit ook verswak). Begin ideaal gesproke by 0 en **maak dit geleidelik groter totdat** die **geraas** wat bygevoeg word **groter** is as die **verbetering van die sein** wat jy nodig het.

![SigDigger se tunerbeheer is verstel om die vasgevangde radiosein te verbeter](<../../images/image (1099).png>)

### Sinchroniseer met ’n radiokanaal

Sinchroniseer met die kanaal waarna jy wil luister met [**SigDigger** ](https://github.com/BatchDrake/SigDigger), stel die "Baseband audio preview"-opsie in, stel die bandwydte in om al die gestuurde inligting te kry, en stel dan die Tuner op die vlak voordat die geraas werklik begin toeneem:<sup>[[1]](#references)</sup>

![SigDigger-radiokanaal gesinchroniseer met baseband-audiovoorskou en gekonfigureerde bandwydte](<../../images/image (585).png>)

## Interessante truuks

- Wanneer ’n toestel inligting in bursts stuur, is die **eerste deel gewoonlik ’n preamble**. Jy hoef dus **nie bekommerd te wees** as jy **nie inligting** daarin **vind nie, of as daar foute** is.
- In inligtingsrame behoort jy gewoonlik **verskillende rame te vind wat goed met mekaar belyn is**:

![Sinchroniseer met ’n radiokanaal - Interessante truuks: In inligtingsrame behoort jy gewoonlik verskillende rame te vind wat goed met mekaar belyn is](<../../images/image (1076).png>)

![Sinchroniseer met ’n radiokanaal - Interessante truuks: In inligtingsrame behoort jy gewoonlik verskillende rame te vind wat goed met mekaar belyn is](<../../images/image (597).png>)

- **Nadat jy die vlaktransisies herwin het, sal jy dit moontlik moet dekodeer.** By Manchester-kodering verteenwoordig een transisierigting `0` en die teenoorgestelde rigting `1`; die presiese polariteit hang af van die konvensie wat gebruik word.
- ’n Preamble kan ’n reeks van dieselfde gemonsterde vlak bevat, selfs wanneer die payload Manchester-kodering gebruik. Identifiseer dus die raambegin voordat jy dekodeer.

### Ontdek die modulasietipe met IQ

Daar is 3 maniere om inligting in seine te stoor: deur die **amplitude**, **frekwensie** of **fase** te moduleer.\
As jy ’n sein ondersoek, is daar verskillende maniere om te probeer vasstel wat gebruik word om inligting te stoor (sien meer maniere hieronder), maar ’n goeie manier is om die IQ-grafiek na te gaan.

![SigDigger-IQ-grafiek wat gebruik word om vas te stel of ’n sein amplitude-, frekwensie- of fasemodulasie gebruik](<../../images/image (788).png>)

- **AM opspoor**: As daar byvoorbeeld **2 sirkels** in die IQ-grafiek verskyn (waarskynlik een by 0 en ’n ander by ’n ander amplitude), kan dit beteken dat dit ’n AM-sein is. Dit is omdat die afstand tussen 0 en die sirkel in die IQ-grafiek die amplitude van die sein is, wat dit maklik maak om verskillende gebruikte amplitudes te sien.
- **PM opspoor**: Soos in die vorige prent, beteken klein sirkels wat nie met mekaar verband hou nie waarskynlik dat fasemodulasie gebruik word. Dit is omdat die hoek tussen die punt en 0,0 in die IQ-grafiek die fase van die sein is; dit beteken dus dat 4 verskillende fases gebruik word.
  - Let daarop dat as die inligting versteek is in die feit dat ’n fase verander, en nie in die fase self nie, jy nie verskillende fases duidelik onderskeibaar sal sien nie.
- **FM opspoor**: IQ het nie ’n veld om frekwensies aan te dui nie (afstand vanaf die middelpunt is amplitude en die hoek is fase).\
  Om FM te identifiseer, behoort jy dus **basies net ’n sirkel** in hierdie grafiek te sien.\
  ’n Frekwensieverskuiwing verander boonop die rotasietempo om die IQ-sirkel. In SigDigger kan ’n verandering in rotasiespoed of -rigting dus op FM dui.

## AM-voorbeeld

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Ontdek AM

#### Gaan die omhulsel na

Wanneer jy AM-data met [**SigDigger**](https://github.com/BatchDrake/SigDigger) ondersoek, kan die sein se **omhulsel** duidelike amplitudevlakke toon. Die voorbeeldsein stuur inligting as amplitude-gemoduleerde pulse; een puls lyk só:<sup>[[1]](#references)</sup>

![SigDigger-AM-seinomhulsel met duidelike puls-amplitudevlakke](<../../images/image (590).png>)

En só lyk ’n deel van die simbool saam met die golfvorm:

![Ontdek AM - Gaan die omhulsel na: Só lyk ’n deel van die simbool saam met die golfvorm](<../../images/image (734).png>)

#### Gaan die histogram na

Jy kan **die hele sein** waar die inligting geleë is **selekteer**, die **Amplitude**-modus en **Selection** kies en op **Histogram** klik. Jy sal sien dat slegs 2 duidelike vlakke voorkom.

![SigDigger-amplitudehistogram wat twee duidelike vlakke vir die geselekteerde AM-sein toon](<../../images/image (264).png>)

As jy byvoorbeeld Frequency in plaas van Amplitude in hierdie AM-sein kies, vind jy net 1 frekwensie (dit is onmoontlik dat inligting wat deur frekwensie gemoduleer word net 1 frekwensie gebruik).

![SigDigger-frekwensiehistogram vir die AM-sein wat een frekwensie toon](<../../images/image (732).png>)

As jy baie frekwensies vind, is dit moontlik nie FM nie; die seinfoorkoms is waarskynlik bloot weens die kanaal verander.

#### Met IQ

In hierdie voorbeeld kan jy sien dat daar ’n **groot sirkel** is, maar ook **baie punte in die middel**.

![Gaan die histogram na - Met IQ: In hierdie voorbeeld kan jy sien dat daar ’n groot sirkel is, maar ook baie punte in die middel](<../../images/image (222).png>)

### Kry die simbooltempo

#### Met een simbool

Kies die kleinste interval wat duidelik een simbool bevat en gaan **Selection freq** na. In hierdie voorbeeld is dit 1.013 kHz, ongeveer 1 kHz.

![Kry die simbooltempo - Met een simbool: Kies die kleinste simbool wat jy kan vind (sodat jy seker is dit is net een) en gaan "Selection freq" na. In hierdie geval is dit 1.013 kHz (dus 1 kHz).](<../../images/image (78).png>)

#### Met ’n groep simbole

Jy kan ook die aantal simbole aandui wat jy gaan selekteer, waarna SigDigger die frekwensie van 1 simbool sal bereken (hoe meer simbole geselekteer word, hoe beter waarskynlik). In hierdie geval het ek 10 simbole geselekteer en is "Selection freq" 1.004 kHz:

![SigDigger-simbooltempo-berekening met ’n geselekteerde groep van tien simbole](<../../images/image (1008).png>)

### Kry bisse

Nadat jy AM geïdentifiseer en die **simbooltempo** beraam het, selekteer jy die seingebied, stel amplitudemonstering en die besluitvlakke in, kies **Gardner clock recovery** en druk **Sample**:

![SigDigger se Get Bits-paneel, ingestel vir AM-monstering, simbooltempo en Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** beteken dat die simbooltempo wat jy voorheen gevind het deur intervalle te selekteer, gebruik sal word.
- **Manual** beteken dat die aangeduide simbooltempo gebruik sal word.
- In **Fixed interval selection** dui jy die aantal intervalle aan wat geselekteer moet word, waarna die simbooltempo daaruit bereken word.
- **Gardner clock recovery** is ’n nuttige verstekopsie, maar dit vereis steeds ’n benaderde simbooltempo.

Nadat jy op Sample gedruk het, verskyn dit:

![Met ’n groep simbole - Kry bisse: Dit verskyn nadat jy op Sample gedruk het](<../../images/image (644).png>)

Om SigDigger te wys **waar die omvang** van die vlak wat inligting dra is, klik op die **onderste vlak** en hou die muisknoppie ingedruk tot by die hoogste vlak:

![SigDigger-vlakreeksseleksie van die laer amplitudevlak na die hoër vlak](<../../images/image (439).png>)

As daar byvoorbeeld **4 verskillende amplitud vlakke** was, sou jy **Bits per symbol** op 2 moes stel en van die laagste tot die hoogste vlak moes selekteer.

Laastens kan jy die bisse sien deur die **Zoom** te **verhoog** en die **Row size** te verander (jy kan alles selekteer en kopieer om al die bisse te kry):

![Met ’n groep simbole - Kry bisse: Laastens kan jy die bisse sien deur die Zoom te verhoog en die Row size te verander (jy kan alles selekteer en kopieer om al die bisse te kry)](<../../images/image (276).png>)

As die sein meer as 1 bis per simbool het (byvoorbeeld 2), het SigDigger **geen manier om te weet watter simbool** 00, 01, 10 of 11 is nie. Dit sal dus verskillende **grys skakerings** gebruik om elkeen voor te stel (en as jy die bisse kopieer, sal dit **nommers van 0 tot 3** gebruik; jy sal dit self moet verwerk).

Vir lynkodering soos **Manchester**, vertaal elke geldige transisiepaar (`01` of `10`) na ’n databits volgens die konvensie wat gebruik word.

## FM-voorbeeld

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Ontdek FM

#### Gaan die frekwensies en golfvorm na

Voorbeeld van ’n sein wat inligting stuur wat deur FM gemoduleer is:

![Ontdek FM - Gaan die frekwensies en golfvorm na: Voorbeeld van ’n sein wat inligting stuur wat deur FM gemoduleer is](<../../images/image (725).png>)

Die spektrum toon duidelik **twee frekwensies**, hoewel dit moeilik kan wees om hulle in die tydsdomeingolfvorm te onderskei:

![SigDigger-FM-golfvorm waar die twee frekwensies moeilik direk te onderskei is](<../../images/image (717).png>)

Dit gebeur omdat die opname tussen albei frekwensies gesentreer is, sodat hul frekwensieverskuiwings ongeveer teenoorgesteld is:

![SigDigger-FM-opname wat die twee frekwensies as ongeveer teenoorgesteldes toon](<../../images/image (942).png>)

As die gesinchroniseerde frekwensie **nader aan een frekwensie as aan die ander** is, kan jy die 2 verskillende frekwensies maklik sien:

![Ontdek FM - Gaan die frekwensies en golfvorm na: As die gesinchroniseerde frekwensie nader aan een frekwensie as aan die ander is, kan jy die 2 verskillende frekwensies maklik sien](<../../images/image (422).png>)

![Ontdek FM - Gaan die frekwensies en golfvorm na: As die gesinchroniseerde frekwensie nader aan een frekwensie as aan die ander is, kan jy die 2 verskillende frekwensies maklik sien](<../../images/image (488).png>)

#### Gaan die histogram na

As jy die frekwensiehistogram van die sein met inligting nagaan, kan jy maklik 2 verskillende seine sien:

![Gaan die frekwensies en golfvorm na - Gaan die histogram na: As jy die frekwensiehistogram van die sein met inligting nagaan, kan jy maklik 2 verskillende seine sien](<../../images/image (871).png>)

As jy in hierdie geval die **Amplitude histogram** nagaan, sal jy **slegs een amplitude** vind, dus **kan dit nie AM wees nie** (as jy baie amplitudes vind, kan dit wees omdat die sein deur die kanaal krag verloor het):

![SigDigger-amplitudehistogram vir ’n FM-sein wat ’n enkele amplitudevlak toon](<../../images/image (817).png>)

En só sal die fasehistogram lyk (wat baie duidelik maak dat die sein nie in fase gemoduleer is nie):

![Gaan die frekwensies en golfvorm na - Gaan die histogram na: Só sal die fasehistogram lyk (wat baie duidelik maak dat die sein nie in fase gemoduleer is nie)](<../../images/image (996).png>)

#### Met IQ

IQ het nie ’n veld om frekwensies aan te dui nie (afstand vanaf die middelpunt is amplitude en die hoek is fase).\
Om FM te identifiseer, behoort jy dus **basies net ’n sirkel** in hierdie grafiek te sien.\
’n Frekwensieverskuiwing verander boonop die rotasietempo om die IQ-sirkel. In SigDigger kan ’n verandering in rotasiespoed of -rigting dus op FM dui:

![SigDigger-IQ-grafiek waar FM as veranderings in versnelling om die sirkel verskyn](<../../images/image (81).png>)

### Kry die simbooltempo

Jy kan **dieselfde tegniek as in die AM-voorbeeld** gebruik om die simbooltempo te kry nadat jy die frekwensies gevind het wat die simbole dra.

### Kry bisse

Jy kan **dieselfde tegniek as in die AM-voorbeeld** gebruik om die bisse te kry nadat jy vasgestel het dat die sein **in frekwensie gemoduleer is** en die **simbooltempo** bepaal het.

## References

- [1] [SigDigger - Gratis digitale seinontleder vir GNU/Linux en macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
