# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger) is 'n gratis digitale seinanaliseerder vir GNU/Linux en macOS, ontwerp om inligting van onbekende radiosignale te onttrek. Dit ondersteun 'n verskeidenheid SDR-toestelle deur SoapySDR, en laat aanpasbare demodulasie van FSK, PSK en ASK-signale toe, dekodeer analoog video, analiseer burstige seine en luister na analoog stemkanale (alles in regte tyd).

### Basic Config

Na die installasie is daar 'n paar dinge wat jy kan oorweeg om te konfigureer.\
In instellings (die tweede tab-knoppie) kan jy die **SDR-toestel** kies of **'n lêer kies** om te lees en watter frekwensie om te sintoniseer en die monster tempo (aanbeveel tot 2.56Msps as jou rekenaar dit ondersteun)\\

![](<../../images/image (245).png>)

In die GUI-gedrag is dit aanbeveel om 'n paar dinge in te skakel as jou rekenaar dit ondersteun:

![](<../../images/image (472).png>)

> [!NOTE]
> As jy besef dat jou rekenaar nie dinge opneem nie, probeer om OpenGL te deaktiveer en die monster tempo te verlaag.

### Uses

- Net om **'n bietjie van 'n sein te vang en dit te analiseer**, hou net die knoppie "Push to capture" ingedruk so lank as wat jy nodig het.

![](<../../images/image (960).png>)

- Die **Tuner** van SigDigger help om **beter seine te vang** (maar dit kan ook hulle vererger). Ideaal gesproke begin met 0 en hou **dit groter maak totdat** jy die **ruis** wat ingevoer word, vind wat **groter** is as die **verbetering van die sein** wat jy nodig het).

![](<../../images/image (1099).png>)

### Synchronize with radio channel

Met [**SigDigger** ](https://github.com/BatchDrake/SigDigger) sinkroniseer met die kanaal wat jy wil hoor, konfigureer die "Baseband audio preview" opsie, konfigureer die bandwydte om al die inligting wat gestuur word te kry en stel dan die Tuner in op die vlak voordat die ruis regtig begin toeneem:

![](<../../images/image (585).png>)

## Interesting tricks

- Wanneer 'n toestel inligting in bursts stuur, is die **eerste deel gewoonlik 'n preamble**, so jy **hoef nie** te **sorg** as jy **nie inligting** daar vind **of as daar 'n paar foute** daar is nie.
- In rame van inligting behoort jy gewoonlik **verskillende rame goed uitgelijnd tussen hulle** te vind:

![](<../../images/image (1076).png>)

![](<../../images/image (597).png>)

- **Nadat jy die bits herstel het, moet jy dit op een of ander manier verwerk**. Byvoorbeeld, in Manchester-kodering sal 'n up+down 'n 1 of 0 wees en 'n down+up sal die ander een wees. So pare van 1s en 0s (ups en downs) sal 'n werklike 1 of 'n werklike 0 wees.
- Selfs as 'n sein Manchester-kodering gebruik (dit is onmoontlik om meer as twee 0s of 1s agtereenvolgens te vind), kan jy **verskeie 1s of 0s saam in die preamble vind**!

### Uncovering modulation type with IQ

Daar is 3 maniere om inligting in seine te stoor: Modulerende die **amplitude**, **frekwensie** of **fase**.\
As jy 'n sein nagaan, is daar verskillende maniere om te probeer uit te vind wat gebruik word om inligting te stoor (vind meer maniere hieronder), maar 'n goeie een is om die IQ-grafiek na te gaan.

![](<../../images/image (788).png>)

- **Detecting AM**: As daar in die IQ-grafiek byvoorbeeld **2 sirkels** verskyn (waarskynlik een in 0 en een in 'n ander amplitude), kan dit beteken dat dit 'n AM-sein is. Dit is omdat in die IQ-grafiek die afstand tussen die 0 en die sirkel die amplitude van die sein is, so dit is maklik om verskillende amplitudes wat gebruik word, te visualiseer.
- **Detecting PM**: Soos in die vorige beeld, as jy klein sirkels vind wat nie met mekaar verband hou nie, beteken dit waarskynlik dat 'n fase-modulasie gebruik word. Dit is omdat in die IQ-grafiek, die hoek tussen die punt en die 0,0 die fase van die sein is, so dit beteken dat 4 verskillende fases gebruik word.
- Let daarop dat as die inligting versteek is in die feit dat 'n fase verander en nie in die fase self nie, jy nie verskillende fases duidelik gedifferensieer sal sien nie.
- **Detecting FM**: IQ het nie 'n veld om frekwensies te identifiseer nie (afstand tot sentrum is amplitude en hoek is fase).\
Daarom, om FM te identifiseer, moet jy **basies net 'n sirkel** in hierdie grafiek sien.\
Boonop word 'n ander frekwensie "verteenwoordig" deur die IQ-grafiek deur 'n **spoedversnelling oor die sirkel** (so in SysDigger, wanneer jy die sein kies, word die IQ-grafiek bevolk, as jy 'n versnelling of rigtingverandering in die geskepte sirkel vind, kan dit beteken dat dit FM is):

## AM Example

{% file src="../../images/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Uncovering AM

#### Checking the envelope

Kontroleer AM-inligting met [**SigDigger** ](https://github.com/BatchDrake/SigDigger) en net kyk na die **omhulsel** kan jy verskillende duidelike amplitude vlakke sien. Die gebruikte sein stuur pulse met inligting in AM, so lyk een puls:

![](<../../images/image (590).png>)

En so lyk 'n deel van die simbool met die golfvorm:

![](<../../images/image (734).png>)

#### Checking the Histogram

Jy kan **die hele sein** waar inligting geleë is, kies, **Amplitude** modus en **Seleksie** kies en op **Histogram** klik. Jy kan waarneem dat 2 duidelike vlakke net gevind word

![](<../../images/image (264).png>)

Byvoorbeeld, as jy Frekwensie kies in plaas van Amplitude in hierdie AM-sein, vind jy net 1 frekwensie (geen manier dat inligting wat in frekwensie gemoduleer is, net 1 frekwensie gebruik).

![](<../../images/image (732).png>)

As jy 'n klomp frekwensies vind, sal dit waarskynlik nie 'n FM wees nie, waarskynlik is die seinfrekwensie net gewysig as gevolg van die kanaal.

#### With IQ

In hierdie voorbeeld kan jy sien hoe daar 'n **groot sirkel** is, maar ook **'n klomp punte in die sentrum.**

![](<../../images/image (222).png>)

### Get Symbol Rate

#### With one symbol

Kies die kleinste simbool wat jy kan vind (sodat jy seker is dit is net 1) en kyk na die "Seleksie frekwensie". In hierdie geval sou dit 1.013kHz wees (so 1kHz).

![](<../../images/image (78).png>)

#### With a group of symbols

Jy kan ook die aantal simbole wat jy gaan kies, aandui en SigDigger sal die frekwensie van 1 simbool bereken (hoe meer simbole gekies, hoe beter waarskynlik). In hierdie scenario het ek 10 simbole gekies en die "Seleksie frekwensie" is 1.004 Khz:

![](<../../images/image (1008).png>)

### Get Bits

Aangesien dit 'n **AM-gemoduleerde** sein is en die **simbooltempo** (en wetende dat in hierdie geval iets op beteken 1 en iets af beteken 0), is dit baie maklik om die **bits** wat in die sein gekodeer is, te **verkry**. So, kies die sein met inligting en konfigureer die monster en besluit en druk monster (kyk dat **Amplitude** gekies is, die ontdekte **Simbooltempo** is geconfigureer en die **Gadner klokherstel** is gekies):

![](<../../images/image (965).png>)

- **Sync to selection intervals** beteken dat as jy voorheen intervalle gekies het om die simbooltempo te vind, daardie simbooltempo gebruik sal word.
- **Manual** beteken dat die aangeduide simbooltempo gebruik gaan word
- In **Fixed interval selection** dui jy die aantal intervalle aan wat gekies moet word en dit bereken die simbooltempo daarvan
- **Gadner clock recovery** is gewoonlik die beste opsie, maar jy moet steeds 'n paar benaderde simbooltempo aandui.

Wanneer jy op monster druk, verskyn dit:

![](<../../images/image (644).png>)

Nou, om SigDigger te laat verstaan **waar die reeks** van die vlak wat inligting dra, moet jy op die **lae vlak** klik en ingedruk hou totdat die grootste vlak:

![](<../../images/image (439).png>)

As daar byvoorbeeld **4 verskillende vlakke van amplitude** was, sou jy die **Bits per simbool op 2** moes konfigureer en van die kleinste na die grootste kies.

Laastens **verhoog** die **Zoom** en **verander die Ry-grootte** kan jy die bits sien (en jy kan alles kies en kopieer om al die bits te kry):

![](<../../images/image (276).png>)

As die sein meer as 1 bit per simbool het (byvoorbeeld 2), het SigDigger **geen manier om te weet watter simbool is** 00, 01, 10, 11 nie, so dit sal verskillende **grys skale** gebruik om elkeen te verteenwoordig (en as jy die bits kopieer, sal dit **nommers van 0 tot 3** gebruik, jy sal dit moet verwerk).

Gebruik ook **kodering** soos **Manchester**, en **up+down** kan **1 of 0** wees en 'n down+up kan 'n 1 of 0 wees. In daardie gevalle moet jy die **verkrygde ups (1) en downs (0)** verwerk om die pare van 01 of 10 as 0s of 1s te vervang.

## FM Example

{% file src="../../images/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Uncovering FM

#### Checking the frequencies and waveform

Seinvoorbeeld wat inligting gemoduleer in FM stuur:

![](<../../images/image (725).png>)

In die vorige beeld kan jy redelik goed waarneem dat **2 frekwensies gebruik word**, maar as jy die **golfvorm** waarneem, mag jy **nie in staat wees om die 2 verskillende frekwensies korrek te identifiseer nie**:

![](<../../images/image (717).png>)

Dit is omdat ek die sein in beide frekwensies opgeneem het, daarom is een ongeveer die ander in negatief:

![](<../../images/image (942).png>)

As die gesinkroniseerde frekwensie **naby aan een frekwensie is as aan die ander**, kan jy maklik die 2 verskillende frekwensies sien:

![](<../../images/image (422).png>)

![](<../../images/image (488).png>)

#### Checking the histogram

Deur die frekwensiehistogram van die sein met inligting na te gaan, kan jy maklik 2 verskillende seine sien:

![](<../../images/image (871).png>)

In hierdie geval, as jy die **Amplitude histogram** nagaan, sal jy **slegs een amplitude** vind, so dit **kan nie AM wees nie** (as jy 'n klomp amplitudes vind, kan dit wees omdat die sein krag langs die kanaal verloor het):

![](<../../images/image (817).png>)

En dit sou die fasehistogram wees (wat baie duidelik maak dat die sein nie in fase gemoduleer is nie):

![](<../../images/image (996).png>)

#### With IQ

IQ het nie 'n veld om frekwensies te identifiseer nie (afstand tot sentrum is amplitude en hoek is fase).\
Daarom, om FM te identifiseer, moet jy **basies net 'n sirkel** in hierdie grafiek sien.\
Boonop word 'n ander frekwensie "verteenwoordig" deur die IQ-grafiek deur 'n **spoedversnelling oor die sirkel** (so in SysDigger, wanneer jy die sein kies, word die IQ-grafiek bevolk, as jy 'n versnelling of rigtingverandering in die geskepte sirkel vind, kan dit beteken dat dit FM is):

![](<../../images/image (81).png>)

### Get Symbol Rate

Jy kan die **dieselfde tegniek as die een wat in die AM-voorbeeld gebruik is** gebruik om die simbooltempo te kry sodra jy die frekwensies wat simbole dra, gevind het.

### Get Bits

Jy kan die **dieselfde tegniek as die een wat in die AM-voorbeeld gebruik is** gebruik om die bits te kry sodra jy **gevind het dat die sein in frekwensie gemoduleer is** en die **simbooltempo**.

{{#include ../../banners/hacktricks-training.md}}
