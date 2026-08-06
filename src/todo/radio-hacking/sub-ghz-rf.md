# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Motorhuisdeure

Motorhuisdeuropeners werk tipies in die 300-190 MHz-reeks, met die algemeenste frekwensies 300 MHz, 310 MHz, 315 MHz en 390 MHz. Hierdie frekwensiereeks word algemeen vir motorhuisdeuropeners gebruik omdat dit minder beset is as ander frekwensiebande en minder geneig is om steuring van ander toestelle te ervaar.

## Motordeure

Die meeste motorsleutel-fobs werk óf op **315 MHz óf 433 MHz**. Albei is radiofrekwensies en word in ’n verskeidenheid toepassings gebruik. Die belangrikste verskil tussen die twee frekwensies is dat 433 MHz ’n langer reikwydte as 315 MHz het. Dit beteken dat 433 MHz beter is vir toepassings wat ’n langer reikwydte vereis, soos afstandbeheerde sleutellose toegang.\
In Europa word 433.92MHz algemeen gebruik, en in die V.S. en Japan word 315MHz gebruik.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

As jy, in plaas daarvan om elke kode 5 keer te stuur (dit word so gestuur om seker te maak dat die ontvanger dit ontvang), dit net een keer stuur, word die tyd tot 6 minute verminder:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

en as jy die **2 ms-wagperiode** tussen seine **verwyder**, kan jy **die tyd tot 3 minute verminder.**

Verder, deur die De Bruijn Sequence te gebruik (’n manier om die aantal bisse wat nodig is om al die moontlike binêre getalle te stuur vir bruteforce te verminder), word hierdie **tyd tot slegs 8 sekondes verminder**:<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

’n Voorbeeld van hierdie aanval is geïmplementeer in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Die vereiste van **’n preamble sal die De Bruijn Sequence**-optimalisering voorkom, en **rolling codes sal hierdie aanval voorkom** (met die aanname dat die kode lank genoeg is om nie bruteforceable te wees nie).

## Sub-GHz Attack

Om hierdie seine met Flipper Zero aan te val, kyk na:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes-beskerming

Outomatiese motorhuisdeuropeners gebruik tipies ’n wireless remote control om die motorhuisdeur oop en toe te maak. Die remote control **stuur ’n radiofrekwensie- (RF-) sein** na die motorhuisdeuropener, wat die motor aktiveer om die deur oop of toe te maak.

Dit is moontlik vir iemand om ’n toestel, bekend as ’n code grabber, te gebruik om die RF-sein te onderskep en dit vir latere gebruik op te neem. Dit staan as ’n **replay attack** bekend. Om hierdie soort aanval te voorkom, gebruik baie moderne motorhuisdeuropeners ’n veiliger encryption-metode, bekend as ’n **rolling code**-stelsel.

Die **RF-sein word tipies met ’n rolling code versend**, wat beteken dat die kode met elke gebruik verander. Dit maak dit **moeilik** vir iemand om die sein te **onderskep** en dit te **gebruik** om **ongemagtigde** toegang tot die motorhuis te verkry.

In ’n rolling code-stelsel het die remote control en die motorhuisdeuropener ’n **gedeelde algoritme** wat elke keer wanneer die remote gebruik word **’n nuwe kode genereer**. Die motorhuisdeuropener sal slegs op die **korrekte kode** reageer, wat dit baie moeiliker maak vir iemand om ongemagtigde toegang tot die motorhuis te verkry bloot deur ’n kode vas te lê.

### **Missing Link Attack**

Basies luister jy vir die knoppie en **vang jy die sein vas terwyl die remote buite die reikwydte** van die toestel (byvoorbeeld die motor of motorhuis) is. Daarna beweeg jy na die toestel en **gebruik jy die vasgelegde kode om dit oop te maak**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

’n Aanvaller kan die **sein naby die voertuig of ontvange**r **jam**, sodat die **ontvanger nie werklik die kode kan “hoor” nie**, en sodra dit gebeur, kan jy eenvoudig die kode **vaslê en replay** wanneer jy ophou jam.<sup>[[2]](#references)</sup>

Die slagoffer sal op ’n stadium die **sleutels gebruik om die motor te sluit**, maar die aanval sal dan **genoeg “sluitdeur”-kodes opgeneem** hê wat hopelik weer gestuur kan word om die deur oop te maak (’n **verandering van frekwensie mag nodig wees**, aangesien daar motors is wat dieselfde kodes gebruik om oop en toe te maak, maar na albei opdragte op verskillende frekwensies luister).

> [!WARNING]
> **Jamming werk**, maar dit is opvallend, want as die **persoon wat die motor sluit eenvoudig die deure toets** om seker te maak dat hulle gesluit is, sal hulle agterkom dat die motor ontsluit is. Daarbenewens, as hulle van sulke aanvalle bewus was, kon hulle selfs opmerk dat die deure nooit die **sluitgeluid** gemaak het nie of dat die motor se **ligte** nooit geflits het toe hulle die “lock”-knoppie gedruk het nie.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Dit is ’n meer **stealth Jamming-tegniek**. Die aanvaller sal die sein jam, sodat dit nie sal werk wanneer die slagoffer probeer om die deur te sluit nie, maar die aanvaller sal **hierdie kode opneem**. Daarna sal die slagoffer **weer probeer om die motor te sluit** deur die knoppie te druk, en die motor sal **hierdie tweede kode opneem**.<sup>[[2]](#references)[[4]](#references)</sup>\
Onmiddellik daarna kan die **aanvaller die eerste kode stuur**, en die **motor sal sluit** (die slagoffer sal dink dat die tweede druk die motor gesluit het). Daarna sal die aanvaller die **tweede gesteelde kode kan stuur om die** motor **oop te maak** (met die aanname dat ’n **“sluit motor”-kode ook gebruik kan word om dit oop te maak**). ’n Verandering van frekwensie mag nodig wees (aangesien daar motors is wat dieselfde kodes gebruik om oop en toe te maak, maar na albei opdragte op verskillende frekwensies luister).

Die aanvaller kan die motor se ontvanger **jam en nie sy eie ontvanger nie**, want as die motor se ontvanger byvoorbeeld na ’n 1MHz-breëband luister, sal die aanvaller nie die presiese frekwensie wat deur die remote gebruik word **jam** nie, maar **’n nabygeleë een in daardie spektrum**, terwyl die **aanvaller se ontvanger na ’n kleiner reeks sal luister** waar hy die remote se sein **sonder die jams sein** kan hoor.

> [!WARNING]
> Ander implementerings wat in spesifikasies gesien is, toon dat die **rolling code ’n gedeelte** van die totale gestuurde kode is. Die gestuurde kode is byvoorbeeld ’n **24-bis-sleutel**, waar die eerste **12 die rolling code** is, die **volgende 8 die opdrag** (soos lock of unlock) en die laaste 4 die **checksum** is. Voertuie wat hierdie tipe implementeer, is ook natuurlik vatbaar, aangesien die aanvaller slegs die rolling code-segment hoef te vervang om enige rolling code op albei frekwensies te kan **gebruik**.

> [!CAUTION]
> Let daarop dat as die slagoffer ’n derde kode stuur terwyl die aanvaller die eerste een stuur, die eerste en tweede kode ongeldig gemaak sal word.

### Alarm Sounding Jamming Attack

Tydens toetsing teen ’n aftermarket rolling code-stelsel wat op ’n motor geïnstalleer was, het die **stuur van dieselfde kode twee keer** die alarm en immobiliseerder **onmiddellik geaktiveer**, wat ’n unieke geleentheid vir **denial of service** gebied het. Ironies genoeg was die manier om die alarm en immobiliseerder **te deaktiveer** om die **remote** te **druk**, wat ’n aanvaller die vermoë gegee het om voortdurend ’n DoS-aanval uit te voer. Of kombineer hierdie aanval met die **vorige een om meer kodes te verkry**, aangesien die slagoffer die aanval so gou moontlik sou wou stop.<sup>[[2]](#references)</sup>

## Verwysings

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [How To Hack A Car - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
