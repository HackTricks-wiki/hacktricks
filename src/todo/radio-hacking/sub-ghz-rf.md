# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

Garage-deur-afstandbeheerders gebruik verskeie streek- en produkspesifieke sub-GHz-toewysings. Frekwensies soos 300, 310, 315, 390 en 433.92 MHz kom voor, maar daar is geen universele “300–190 MHz”-garage-deur-band nie. Identifiseer die teiken se etiket, regulatoriese streek en waargenome sein voordat jy uitsaai.<sup>[[1]](#references)</sup>

## Car Doors

Baie motorsleutelhouers gebruik **315 MHz of 433.92 MHz**, met streeksreëls en voertuigontwerp wat die keuse beïnvloed. Frekwensie alleen maak 433 MHz nie verder reikend as 315 MHz nie: uitsaaikrag, antenna-doeltreffendheid, modulasie, ontvangersensitiwiteit, voortplanting en plaaslike regulasies speel almal ’n rol. Europa gebruik algemeen 433.92 MHz, terwyl 315 MHz algemeen in Noord-Amerika en Japan is.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

In die gedemonstreerde vastekode-stelsel verminder die stuur van elke kode een keer, in plaas van vyf keer, die geskatte tyd tot ses minute:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Deur die wag van 2 ms tussen seine te verwyder, verminder die demonstrasie tot ongeveer drie minute.

Die gebruik van ’n De Bruijn sequence om kandidaat-bitstringe te oorvleuel, verminder die gedemonstreerde aanval tot ongeveer agt sekondes wanneer die ontvanger die aaneenlopende sequence aanvaar sonder ’n vereiste preamble of frame reset.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implementeer hierdie aanval teen versoenbare vastekode-stelsels.<sup>[[5]](#references)</sup>

Die vereiste van **’n preamble sal die De Bruijn Sequence**-optimering voorkom, en **rolling codes sal hierdie aanval verhoed** (met die veronderstelling dat die kode lank genoeg is om nie brute-forceable te wees nie).

## Sub-GHz Attack

Om hierdie seine met Flipper Zero aan te val, kyk na:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Outomatiese garage-deur-openers gebruik gewoonlik ’n draadlose afstandbeheerder om die garage-deur oop en toe te maak. Die afstandbeheerder **stuur ’n radiofrekwensie- (RF-) sein** na die garage-deur-opener, wat die motor aktiveer om die deur oop of toe te maak.

Dit is moontlik vir iemand om ’n toestel, bekend as ’n code grabber, te gebruik om die RF-sein te onderskep en dit vir latere gebruik op te neem. Dit staan bekend as ’n **replay attack**. Om hierdie soort aanval te voorkom, gebruik baie moderne garage-deur-openers ’n veiliger encryption-metode, bekend as ’n **rolling code**-stelsel.

Die **RF-sein word tipies met ’n rolling code gestuur**, wat beteken dat die kode met elke gebruik verander. Dit maak dit **moeilik** vir iemand om die sein te **onderskep** en dit te **gebruik** om **ongemagtigde** toegang tot die garage te verkry.

In ’n rolling code-stelsel het die afstandbeheerder en die garage-deur-opener ’n **gedeelde algoritme** wat elke keer wanneer die afstandbeheerder gebruik word, ’n **nuwe kode genereer**. Die garage-deur-opener sal slegs op die **korrekte kode** reageer, wat dit baie moeiliker maak vir iemand om ongemagtigde toegang tot die garage te verkry bloot deur ’n kode vas te lê.

### **Missing Link Attack**

Basies luister jy vir die knoppie en **vang jy die sein op terwyl die afstandbeheerder buite bereik** van die toestel (byvoorbeeld die motor of garage) is. Jy beweeg dan na die toestel en **gebruik die vasgelegde kode om dit oop te maak**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> Opsetlike RF-interferensie is in baie jurisdiksies onwettig en kan veiligheidsrelevante stelsels ontwrig. Voer jamming-toetse slegs in ’n afgeskermde, gemagtigde laboratorium en volgens die toepaslike radioregulasies uit.<sup>[[6]](#references)</sup>

’n Aanvaller kan **die sein naby die voertuig of ontvanger jam** sodat die ontvanger nie die kode kan dekodeer nie, die geblokkeerde transmissie afsonderlik opneem, ophou jam en dan die vasgelegde kode herafspeel.<sup>[[2]](#references)</sup>

Die slagoffer sal op ’n stadium die **sleutels gebruik om die motor te sluit**, maar teen daardie tyd sal die aanval **genoeg “close door”-kodes opgeneem hê** wat hopelik weer gestuur kan word om die deur oop te maak (’n **frekwensieverandering kan nodig wees**, aangesien daar motors is wat dieselfde kodes gebruik om oop en toe te maak, maar vir die twee opdragte op verskillende frekwensies luister).

> [!WARNING]
> **Jamming werk**, maar dit is opvallend: as die **persoon wat die motor sluit eenvoudig die deure toets** om seker te maak dat hulle gesluit is, sal hulle agterkom dat die motor ontsluit is. As hulle boonop van sulke aanvalle bewus is, kan hulle selfs agterkom dat die deure nooit die sluitoorgang **geluid** gemaak het nie, of dat die motor se **ligte** nooit geflits het toe hulle die ‘lock’-knoppie gedruk het nie.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Dit is ’n meer **stealth Jamming-tegniek**. Die aanvaller sal die sein jam, sodat dit nie werk wanneer die slagoffer probeer om die deur te sluit nie, maar die aanvaller sal **hierdie kode opneem**. Die slagoffer sal dan **weer probeer om die motor te sluit** deur die knoppie te druk, en die motor sal **hierdie tweede kode opneem**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Onmiddellik daarna kan die **aanvaller die eerste kode stuur**, waarna die **motor sal sluit** (die slagoffer sal dink dat die tweede druk dit gesluit het). Die aanvaller sal dan die **tweede gesteelde kode kan stuur om** die motor **oop te maak** (met die veronderstelling dat ’n **“close car”-kode ook gebruik kan word om dit oop te maak**). ’n Frekwensieverandering kan nodig wees (aangesien daar motors is wat dieselfde kodes gebruik om oop en toe te maak, maar vir die twee opdragte op verskillende frekwensies luister).

Een RollJam-implementering buit ontvangerbandwydte uit: die jammer saai naby genoeg aan die afstandbeheerder se draer uit om die voertuig se wyer ontvanger onsensitief te maak, terwyl die aanvaller se nouer ontvanger op die afstandbeheerder gesentreer bly en dit steeds kan opneem. Die presiese afwyking en bandwydte hang van die teikenhardeware af.<sup>[[2]](#references)</sup>

> [!WARNING]
> Ander implementerings wat in spesifikasies gesien word, toon dat die **rolling code ’n gedeelte** van die totale gestuurde kode is. Die gestuurde kode is byvoorbeeld ’n **24-bit-sleutel** waarvan die eerste **12 die rolling code** is, die **volgende 8 die opdrag** (soos lock of unlock) en die laaste 4 die **checksum**. Voertuie wat hierdie tipe implementeer, is ook natuurlik vatbaar, aangesien die aanvaller bloot die rolling code-segment hoef te vervang om enige rolling code op albei frekwensies te kan **gebruik**.

> [!CAUTION]
> Let daarop dat indien die slagoffer ’n derde kode stuur terwyl die aanvaller die eerste een stuur, die eerste en tweede kode ongeldig gemaak sal word.

### Alarm Sounding Jamming Attack

Tydens toetsing teen ’n aftermarket rolling code-stelsel wat op ’n motor geïnstalleer is, het die **twee keer onmiddellik stuur van dieselfde kode** die **alarm en immobiliseerder geaktiveer**, wat ’n unieke **denial of service**-geleentheid gebied het. Ironies genoeg was die manier om die **alarm** en immobiliseerder **te deaktiveer** om die **afstandbeheerder te druk**, wat ’n aanvaller die vermoë gegee het om voortdurend ’n DoS-aanval uit te voer. Of kombineer hierdie aanval met die **vorige een om meer kodes te verkry**, aangesien die slagoffer die aanval so gou moontlik sal wil stop.<sup>[[2]](#references)</sup>

## References

- [1] [Flipper Zero-dokumentasie - streekgebaseerde Sub-GHz-frekwensies](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Omseiling van Rolling Code-stelsels - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Hoe om ’n motor te hack - RollJam-herimplementering met YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [OpenSesame-bronkode](https://github.com/samyk/opensesame)
- [6] [FCC Enforcement Advisory - Jammer Enforcement](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
