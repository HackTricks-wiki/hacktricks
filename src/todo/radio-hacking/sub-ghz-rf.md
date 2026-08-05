# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Motorhuisdeure

Motorhuisdeur-openers werk tipies in die 300-190 MHz-reeks, met die algemeenste frekwensies 300 MHz, 310 MHz, 315 MHz en 390 MHz. Hierdie frekwensiereeks word algemeen vir motorhuisdeur-openers gebruik omdat dit minder besig is as ander frekwensiebande en minder geneig is om interferensie van ander toestelle te ondervind.

## Motordeure

Die meeste motorsleutel-fobs werk op óf **315 MHz óf 433 MHz**. Dit is albei radiofrekwensies en word in verskeie toepassings gebruik. Die belangrikste verskil tussen die twee frekwensies is dat 433 MHz ’n langer reikwydte as 315 MHz het. Dit beteken dat 433 MHz beter is vir toepassings wat ’n langer reikwydte vereis, soos remote keyless entry.\
In Europa word 433.92MHz algemeen gebruik, en in die VSA en Japan is dit 315MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

As elke kode eerder net een keer gestuur word as om elke kode 5 keer te stuur (dit word so gestuur om seker te maak dat die ontvanger dit ontvang), word die tyd tot 6 minute verminder:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

en as jy die **2 ms-wagperiode** tussen seine **verwyder**, kan jy **die tyd tot 3 minute verminder.**

Deur die De Bruijn Sequence te gebruik (’n manier om die aantal bisse wat nodig is om al die moontlike binêre getalle te stuur en te brute-force, te verminder), word hierdie **tyd tot slegs 8 sekondes verminder**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

’n Voorbeeld van hierdie aanval is geïmplementeer in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)<sup>[[3]](#references)</sup>

’n **Preamble sal die De Bruijn Sequence**-optimalisering voorkom, en **rolling codes sal hierdie aanval verhoed** (met die veronderstelling dat die kode lank genoeg is om nie brute-forcebaar te wees nie).

## Sub-GHz Attack

Om hierdie seine met Flipper Zero aan te val, kyk na:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Outomatiese motorhuisdeur-openers gebruik tipies ’n wireless remote control om die motorhuisdeur oop en toe te maak. Die remote control **stuur ’n radiofrekwensie- (RF-) sein** na die motorhuisdeur-opener, wat die motor aktiveer om die deur oop of toe te maak.

Dit is moontlik vir iemand om ’n toestel, bekend as ’n code grabber, te gebruik om die RF-sein te onderskep en dit vir latere gebruik op te neem. Dit staan bekend as ’n **replay attack**. Om hierdie tipe aanval te voorkom, gebruik baie moderne motorhuisdeur-openers ’n veiliger encryption-metode, bekend as ’n **rolling code**-stelsel.

Die **RF-sein word tipies met ’n rolling code gestuur**, wat beteken dat die kode met elke gebruik verander. Dit maak dit **moeilik** vir iemand om die sein te **onderskep** en dit te **gebruik** om **ongemagtigde** toegang tot die motorhuis te verkry.

In ’n rolling code-stelsel het die remote control en die motorhuisdeur-opener ’n **gedeelde algoritme** wat elke keer wanneer die remote gebruik word, ’n **nuwe kode genereer**. Die motorhuisdeur-opener sal slegs op die **korrekte kode** reageer, wat dit baie moeiliker maak vir iemand om ongemagtigde toegang tot die motorhuis te verkry bloot deur ’n kode vas te lê.

### **Missing Link Attack**

Basies luister jy vir die knoppie en **vang die sein vas terwyl die remote buite die reikwydte** van die toestel (byvoorbeeld die motor of motorhuis) is. Jy beweeg dan na die toestel en **gebruik die vasgevangde kode om dit oop te maak**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

’n Aanvaller kan die sein naby die voertuig of **ontvang**er **versteur**, sodat die **ontvanger nie werklik die kode kan ‘hoor’ nie**, en sodra dit gebeur, kan jy eenvoudig die kode **vaslê en herstuur** wanneer jy opgehou het om te versteur.

Die slagoffer sal op ’n stadium die **sleutels gebruik om die motor te sluit**, maar die aanval sal dan **genoeg "close door"-kodes opgeneem** hê wat hopelik weer gestuur kan word om die deur oop te maak (’n **frekwensieverandering mag nodig wees**, aangesien daar motors is wat dieselfde kodes gebruik om oop en toe te maak, maar na albei opdragte op verskillende frekwensies luister).

> [!WARNING]
> **Jamming werk**, maar dit is opvallend, want as die **persoon wat die motor sluit eenvoudig die deure toets** om seker te maak dat hulle gesluit is, sal hulle agterkom dat die motor oopgesluit is. Indien hulle ook van sulke aanvalle bewus is, kan hulle selfs opmerk dat die deure nooit die **sluitgeluid** gemaak het nie of dat die motor se **ligte** nooit geflits het toe hulle die ‘lock’-knoppie gedruk het nie.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Dit is ’n meer **stealth Jamming technique**. Die aanvaller sal die sein versteur, sodat dit nie sal werk wanneer die slagoffer die deur probeer sluit nie, maar die aanvaller sal **hierdie kode opneem**. Die slagoffer sal dan weer probeer om die motor te sluit deur die knoppie te druk, en die motor sal **hierdie tweede kode opneem**.\
Onmiddellik daarna kan die **aanvaller die eerste kode stuur**, en die **motor sal sluit** (die slagoffer sal dink dat die tweede druk dit gesluit het). Die aanvaller sal dan die **tweede gesteelde kode kan stuur om die** motor oop te maak (met die veronderstelling dat ’n **"close car"-kode ook gebruik kan word om dit oop te maak**). ’n Frekwensieverandering mag nodig wees (aangesien daar motors is wat dieselfde kodes gebruik om oop en toe te maak, maar na albei opdragte op verskillende frekwensies luister).<sup>[[3]](#references)[[2]](#references)</sup>

Die aanvaller kan die motor se ontvanger **versteur, maar nie sy eie ontvanger nie**, want as die motor se ontvanger byvoorbeeld na ’n 1MHz-breëband luister, sal die aanvaller nie die presiese frekwensie wat deur die remote gebruik word **jam** nie, maar **’n nabygeleë frekwensie in daardie spektrum**, terwyl die **aanvaller se ontvanger na ’n kleiner reeks sal luister** waar hy die remote-sein **sonder die jam-sein** kan hoor.

> [!WARNING]
> Ander implementerings wat in spesifikasies gesien is, wys dat die **rolling code slegs ’n gedeelte** van die totale gestuurde kode is. Die gestuurde kode is byvoorbeeld ’n **24-bis-sleutel**, waar die eerste **12 die rolling code** is, die **volgende 8 die opdrag** (soos lock of unlock), en die laaste 4 die **checksum** is. Voertuie wat hierdie tipe implementeer, is ook natuurlik vatbaar, aangesien die aanvaller slegs die rolling code-segment hoef te vervang om **enige rolling code op albei frekwensies te kan gebruik**.

> [!CAUTION]
> Let daarop dat indien die slagoffer ’n derde kode stuur terwyl die aanvaller die eerste een stuur, die eerste en tweede kode ongeldig gemaak sal word.

### Alarm Sounding Jamming Attack

In toetse teen ’n aftermarket rolling code-stelsel wat op ’n motor geïnstalleer is, het die **twee keer onmiddellik stuur van dieselfde kode** die alarm en immobiliser **geaktiveer**, wat ’n unieke **denial of service**-geleentheid gebied het. Ironies genoeg was die manier om die alarm en immobiliser **te deaktiveer** om die **remote te druk**, wat ’n aanvaller die vermoë gegee het om voortdurend ’n **DoS attack uit te voer**. Of kombineer hierdie aanval met die **vorige een om meer kodes te verkry**, aangesien die slagoffer die aanval so gou moontlik sal wil stop.<sup>[[2]](#references)</sup>

## Verwysings

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Drive It Like You Hacked It (DEF CON 23) - OpenSesame / RollJam](https://samy.pl/defcon2015/)
- [4] [How to hack a car (RollJam recreation)](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
