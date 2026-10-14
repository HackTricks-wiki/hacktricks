# Radio

{{#include ../../banners/hacktricks-training.md}}

Vir protokolspesifieke werk ná seinidentifikasie, sien [toetsing van RFID/NFC, sub-GHz, infrarooi, BLE en LoRaWAN](../radio-hacking/README.md).

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) is ’n gratis digitale seinontleder vir GNU/Linux en macOS wat ontwerp is om inligting uit onbekende radioseine te onttrek. Dit ondersteun SDR-toestelle deur SoapySDR en bied intydse demodulasie- en ontledingsnutsgoed vir FSK, PSK, ASK, analoog video, burst-seine en analoog stemkanale.<sup>[[1]](#references)</sup>

### Basiese konfigurasie

Ná installering is daar ’n paar dinge wat jy dalk wil instel.\
Kies in die instellings (die tweede oortjieknoppie) ’n **SDR-toestel** of ’n invoerlêer, die frekwensie waarop jy wil instel, en die monstertempo. ’n Tempo van tot 2.56 Msps kan prakties wees as die gasheer dit ondersteun.

![SigDigger-instellings wat die SDR-toestel, invoerlêer, frekwensie en monstertempo-opsies wys](<../../images/image (245).png>)

In die GUI-gedraginstellings word dit aanbeveel om ’n paar dinge te aktiveer as jou rekenaar dit ondersteun:

![SigDigger - Basiese konfigurasie: In die GUI-gedraginstellings word dit aanbeveel om ’n paar dinge te aktiveer as jou rekenaar dit ondersteun](<../../images/image (472).png>)

> [!TIP]
> As jy agterkom dat jou rekenaar nie dinge vaslê nie, probeer om OpenGL te deaktiveer en die monstertempo te verlaag.

### Gebruike

- Om **’n sein vir ’n tyd lank vas te lê en te ontleed**, hou die knoppie "Push to capture" net so lank ingedruk as wat nodig is.

![Basiese konfigurasie - Gebruike: Om ’n sein vir ’n tyd lank vas te lê en te ontleed, hou die knoppie "Push to capture" net so lank ingedruk as wat nodig is](<../../images/image (960).png>)

- SigDigger se **Tuner** help om **seine beter vas te lê** (maar kan dit ook verswak). Begin ideaal gesproke by 0 en **verhoog dit** totdat die **geraas** wat bygevoeg word, **groter** is as die **seinverbetering** wat jy nodig het.

![SigDigger se tunerbeheer is aangepas om die vasgelegde radiosein te verbeter](<../../images/image (1099).png>)

### Sinkroniseer met radiokanaal

Met [**SigDigger** ](https://github.com/BatchDrake/SigDigger) sinkroniseer jy met die kanaal waarna jy wil luister, stel die "Baseband audio preview"-opsie in, stel die bandwydte in om al die gestuurde inligting te kry en stel dan die Tuner op die vlak net voordat die geraas werklik begin toeneem:<sup>[[1]](#references)</sup>

![SigDigger is met die radiokanaal gesinkroniseer, met basisbandoudiovoorskou en bandwydte ingestel](<../../images/image (585).png>)

## Interessante truuks

- Wanneer ’n toestel inligting in bursts stuur, is die **eerste deel gewoonlik ’n preamble**. Jy hoef dus **nie bekommerd te wees** as jy **nie inligting daarin vind nie**, of as daar **foute** is.
- In inligtingsrame behoort jy gewoonlik **verskillende rame te vind wat goed met mekaar in lyn is**:

![Sinkroniseer met radiokanaal - Interessante truuks: In inligtingsrame behoort jy gewoonlik verskillende rame te vind wat goed met mekaar in lyn is](<../../images/image (1076).png>)

![Sinkroniseer met radiokanaal - Interessante truuks: In inligtingsrame behoort jy gewoonlik verskillende rame te vind wat goed met mekaar in lyn is](<../../images/image (597).png>)

- **Nadat jy die vlak-oorgange herwin het, moet jy hulle dalk dekodeer.** Met Manchester-kodering verteenwoordig een oorgangsrigting `0` en die teenoorgestelde rigting `1`; die presiese polariteit hang af van die konvensie wat gebruik word.
- ’n Preamble kan ’n reeks van dieselfde gemonsterde vlak bevat, selfs wanneer die payload Manchester-kodering gebruik. Identifiseer dus die raambegin voordat jy dekodeer.

### Bepaal modulasietipe met IQ

Daar is 3 maniere om inligting in seine te stoor: deur die **amplitude**, **frekwensie** of **fase** te moduleer.\
As jy ’n sein ondersoek, is daar verskillende maniere om uit te vind wat gebruik word om inligting te stoor (vind meer maniere hieronder), maar ’n goeie metode is om die IQ-grafiek na te gaan.

![SigDigger se IQ-grafiek word gebruik om vas te stel of ’n sein amplitude-, frekwensie- of fasemodulasie gebruik](<../../images/image (788).png>)

- **Bespeur AM**: As daar byvoorbeeld **2 sirkels** in die IQ-grafiek verskyn (waarskynlik een by 0 en die ander by ’n ander amplitude), kan dit beteken dat dit ’n AM-sein is. Dit is omdat die afstand tussen 0 en die sirkel in die IQ-grafiek die amplitude van die sein is, wat dit maklik maak om die verskillende amplitudes wat gebruik word, te sien.
- **Bespeur PM**: Soos in die vorige beeld, beteken klein sirkels wat nie met mekaar verband hou nie waarskynlik dat fasemodulasie gebruik word. Dit is omdat die hoek tussen die punt en 0,0 in die IQ-grafiek die fase van die sein is, wat beteken dat 4 verskillende fases gebruik word.
  - Let daarop dat as die inligting versteek is in die feit dat ’n fase verander, en nie in die fase self nie, jy nie verskillende fases duidelik van mekaar sal kan onderskei nie.
- **Bespeur FM**: IQ het nie ’n veld om frekwensies te identifiseer nie (afstand vanaf die middelpunt is amplitude en die hoek is fase).\
  Om FM te identifiseer, behoort jy dus **basies net ’n sirkel** in hierdie grafiek te sien.\
  ’n Frekwensie-offset verander boonop die rotasietempo rondom die IQ-sirkel. In SigDigger kan ’n verandering in rotasiespoed of -rigting dus op FM dui.

## AM-voorbeeld

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Bepaal AM

#### Gaan die omhulsel na

Wanneer jy AM-data met [**SigDigger**](https://github.com/BatchDrake/SigDigger) ondersoek, kan die sein se **omhulsel** duidelike amplitudovlakke toon. Die voorbeeldsein stuur inligting as amplitude-gemoduleerde pulse; een puls lyk so:<sup>[[1]](#references)</sup>

![SigDigger se AM-seinomhulsel met duidelike puls-amplitudovlakke](<../../images/image (590).png>)

En so lyk ’n deel van die simbool saam met die golfvorm:

![Bepaal AM - Gaan die omhulsel na: En so lyk ’n deel van die simbool saam met die golfvorm](<../../images/image (734).png>)

#### Gaan die histogram na

Jy kan **die hele seinarea waar die inligting geleë is kies**, die **Amplitude**-modus en **Selection** kies, en op **Histogram** klik. Jy kan sien dat daar slegs 2 duidelike vlakke voorkom.

![SigDigger se amplitudehistogram wat twee duidelike vlakke vir die gekose AM-sein toon](<../../images/image (264).png>)

As jy byvoorbeeld Frequency in plaas van Amplitude vir hierdie AM-sein kies, kry jy net 1 frekwensie (dit maak nie sin dat inligting wat in frekwensie gemoduleer is net 1 frekwensie gebruik nie).

![SigDigger se frekwensiehistogram vir die AM-sein wat een frekwensie toon](<../../images/image (732).png>)

As jy baie frekwensies kry, is dit waarskynlik nie FM nie; die kanaal het waarskynlik net die seinfrekwensie verander.

#### Met IQ

In hierdie voorbeeld kan jy sien dat daar ’n **groot sirkel** is, maar ook **baie punte in die middel**.

![Gaan die histogram na - Met IQ: In hierdie voorbeeld kan jy sien dat daar ’n groot sirkel is, maar ook baie punte in die middel](<../../images/image (222).png>)

### Bepaal simbooltempo

#### Met een simbool

Kies die kleinste interval wat duidelik een simbool bevat en gaan **Selection freq** na. In hierdie voorbeeld is dit 1.013 kHz, ongeveer 1 kHz.

![Bepaal simbooltempo - Met een simbool: Kies die kleinste simbool wat jy kan vind (sodat jy seker is dit is net een) en gaan "Selection freq" na. In hierdie geval is dit 1.013 kHz (dus 1 kHz).](<../../images/image (78).png>)

#### Met ’n groep simbole

Jy kan ook die aantal simbole aandui wat jy gaan kies, waarna SigDigger die frekwensie van 1 simbool bereken (waarskynlik is dit beter hoe meer simbole gekies word). In hierdie geval het ek 10 simbole gekies en is "Selection freq" 1.004 Khz:

![SigDigger bereken die simbooltempo met ’n gekose groep van tien simbole](<../../images/image (1008).png>)

### Kry bisse

Nadat jy AM geïdentifiseer en die **simbooltempo** beraam het, kies die seinarea, stel amplitudemonsterneming en die besluitvlakke in, kies **Gardner clock recovery** en druk **Sample**:

![SigDigger se Get Bits-paneel is ingestel vir AM-monsterneming, simbooltempo en Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** beteken dat as jy voorheen intervalle gekies het om die simbooltempo te bepaal, daardie simbooltempo gebruik sal word.
- **Manual** beteken dat die aangeduide simbooltempo gebruik sal word.
- Met **Fixed interval selection** dui jy die aantal intervalle aan wat gekies moet word, waarna die simbooltempo daaruit bereken word.
- **Gardner clock recovery** is ’n nuttige verstekinstelling, maar vereis steeds ’n benaderde simbooltempo.

Wanneer jy op Sample druk, verskyn dit:

![Met ’n groep simbole - Kry bisse: Wanneer jy op Sample druk, verskyn dit](<../../images/image (644).png>)

Om SigDigger te laat verstaan **waar die omvang van die vlak wat die inligting dra is**, klik op die **laer vlak** en hou die muisknoppie ingedruk terwyl jy tot by die hoogste vlak beweeg:

![SigDigger se keuse van vlakomvang vanaf die laer amplitudovlak tot by die hoër vlak](<../../images/image (439).png>)

As daar byvoorbeeld **4 verskillende amplitudovlakke** was, sou jy **Bits per symbol op 2** moes stel en van die laagste tot die hoogste vlak kies.

Deur die **Zoom** te **verhoog** en die **Row size** te **verander**, kan jy uiteindelik die bisse sien (en jy kan alles kies en kopieer om al die bisse te kry):

![Met ’n groep simbole - Kry bisse: Deur die Zoom te verhoog en die Row size te verander, kan jy uiteindelik die bisse sien (en jy kan alles kies en kopieer om al die bisse te kry)](<../../images/image (276).png>)

As die sein meer as 1 bis per simbool het (byvoorbeeld 2), kan SigDigger **nie weet watter simbool** 00, 01, 10 of 11 is nie. Dit gebruik dus verskillende **grysskakerings** om elkeen voor te stel (en as jy die bisse kopieer, gebruik dit **getalle van 0 tot 3**; jy sal dit self moet verwerk).

Vir lynkodering soos **Manchester**, vertaal elke geldige oorgangspaar (`01` of `10`) na ’n databissie volgens die konvensie wat gebruik word.

## FM-voorbeeld

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Bepaal FM

#### Gaan die frekwensies en golfvorm na

Voorbeeld van ’n sein wat inligting stuur wat in FM gemoduleer is:

![Bepaal FM - Gaan die frekwensies en golfvorm na: Voorbeeld van ’n sein wat inligting stuur wat in FM gemoduleer is](<../../images/image (725).png>)

Die spektrum toon duidelik **twee frekwensies**, hoewel hulle dalk moeilik is om in die tydsdomeingolfvorm te onderskei:

![SigDigger se FM-golfvorm waarin die twee frekwensies moeilik direk onderskei kan word](<../../images/image (717).png>)

Dit gebeur omdat die opname tussen albei frekwensies gesentreer is, en hul frekwensie-offsets dus ongeveer teenoorgestelde waardes het:

![SigDigger se FM-opname waarin die twee frekwensies ongeveer teenoorgestelde waardes het](<../../images/image (942).png>)

As die gesinkroniseerde frekwensie **nader aan een frekwensie as die ander** is, kan jy die 2 verskillende frekwensies maklik sien:

![Bepaal FM - Gaan die frekwensies en golfvorm na: As die gesinkroniseerde frekwensie nader aan een frekwensie as die ander is, kan jy die 2 verskillende frekwensies maklik sien](<../../images/image (422).png>)

![Bepaal FM - Gaan die frekwensies en golfvorm na: As die gesinkroniseerde frekwensie nader aan een frekwensie as die ander is, kan jy die 2 verskillende frekwensies maklik sien](<../../images/image (488).png>)

#### Gaan die histogram na

As jy die frekwensiehistogram van die sein met inligting nagaan, kan jy maklik 2 verskillende seine sien:

![Gaan die frekwensies en golfvorm na - Gaan die histogram na: As jy die frekwensiehistogram van die sein met inligting nagaan, kan jy maklik 2 verskillende seine sien](<../../images/image (871).png>)

As jy in hierdie geval die **Amplitude-histogram** nagaan, sal jy **net een amplitude** kry, dus **kan dit nie AM wees nie** (as jy baie amplitudes kry, kan dit wees omdat die sein krag in die kanaal verloor het):

![SigDigger se amplitudehistogram vir die FM-sein wat ’n enkele amplitudovlak toon](<../../images/image (817).png>)

En dit is hoe die fasehistogram lyk (wat baie duidelik wys dat die sein nie in fase gemoduleer is nie):

![Gaan die frekwensies en golfvorm na - Gaan die histogram na: En dit is hoe die fasehistogram lyk (wat baie duidelik wys dat die sein nie in fase gemoduleer is nie)](<../../images/image (996).png>)

#### Met IQ

IQ het nie ’n veld om frekwensies te identifiseer nie (afstand vanaf die middelpunt is amplitude en die hoek is fase).\
Om FM te identifiseer, behoort jy dus **basies net ’n sirkel** in hierdie grafiek te sien.\
’n Frekwensie-offset verander boonop die rotasietempo rondom die IQ-sirkel. In SigDigger kan ’n verandering in rotasiespoed of -rigting dus op FM dui:

![SigDigger se IQ-grafiek waarin FM as veranderinge in die rotasietempo rondom die sirkel verskyn](<../../images/image (81).png>)

### Bepaal simbooltempo

Jy kan **dieselfde tegniek as in die AM-voorbeeld** gebruik om die simbooltempo te bepaal sodra jy die frekwensies gevind het wat die simbole dra.

### Kry bisse

Jy kan **dieselfde tegniek as in die AM-voorbeeld** gebruik om die bisse te kry sodra jy **vasgestel het dat die sein in frekwensie gemoduleer is** en die **simbooltempo** bepaal het.

## References

- [1] [SigDigger - Gratis digitale seinontleder vir GNU/Linux en macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
