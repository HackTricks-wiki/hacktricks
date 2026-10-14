# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garagedeure

Garagedeurafstandbeheerders gebruik sub-GHz-toewysings wat volgens streek en produk verskil. Frekwensies soos 300, 310, 315, 390 en 433.92 MHz kom voor, maar daar is geen universele “300–190 MHz”-band vir garagedeure nie. Identifiseer die teiken se etiket, regulatoriese streek en waargenome sein voordat jy uitstuur.<sup>[[1]](#references)</sup>

## Motordeure

Baie motorsleutelhangers gebruik **315 MHz of 433.92 MHz**, met streekreëls en voertuigontwerp wat die keuse beïnvloed. Frekwensie alleen beteken nie dat 433 MHz ’n langer reikafstand as 315 MHz het nie: uitsaaikrag, antenna-doeltreffendheid, modulasie, ontvangersensitiwiteit, voortplanting en plaaslike regulasies speel almal ’n rol. Europa gebruik gewoonlik 433.92 MHz, terwyl 315 MHz algemeen in Noord-Amerika en Japan voorkom.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

In die gedemonstreerde fixed-code-stelsel verminder die stuur van elke kode een keer, in plaas van vyf keer, die geskatte tyd tot ses minute:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Deur die wagtyd van 2 ms tussen seine te verwyder, word dié demonstrasie tot ongeveer drie minute verkort.

Die gebruik van ’n De Bruijn-sekwensie om kandidaatbisstringe te laat oorvleuel, verkort die gedemonstreerde aanval tot ongeveer agt sekondes wanneer die ontvanger die aaneenlopende sekwensie aanvaar sonder ’n vereiste preamble of raamherstel.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implementeer hierdie aanval teen versoenbare fixed-code-stelsels.<sup>[[5]](#references)</sup>

’n **Preamble-vereiste sal die De Bruijn Sequence**-optimering verhoed, en **rolling codes sal hierdie aanval voorkom** (met die aanname dat die kode lank genoeg is om nie met brute force gekraak te kan word nie).

## Sub-GHz Attack

Om hierdie seine met Flipper Zero aan te val, kyk na:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Beskerming met Rolling Codes

Outomatiese garagedeuropeners gebruik gewoonlik ’n draadlose afstandbeheerder om die garagedeur oop en toe te maak. Die afstandbeheerder **stuur ’n radiofrekwensie- (RF-) sein** na die garagedeuropener, wat die motor aktiveer om die deur oop of toe te maak.

Iemand kan ’n toestel, bekend as ’n code grabber, gebruik om die RF-sein te onderskep en vir latere gebruik op te neem. Dit staan bekend as ’n **replay attack**. Om hierdie soort aanval te voorkom, gebruik baie moderne garagedeuropeners ’n veiliger enkripsiemetode, bekend as ’n **rolling code**-stelsel.

Die **RF-sein word gewoonlik met ’n rolling code uitgestuur**, wat beteken dat die kode met elke gebruik verander. Dit maak dit **moeilik** vir iemand om die sein te **onderskep** en te **gebruik** om **ongemagtigde** toegang tot die garage te verkry.

In ’n rolling code-stelsel het die afstandbeheerder en garagedeuropener ’n **gedeelde algoritme** wat **elke keer wanneer die afstandbeheerder gebruik word ’n nuwe kode genereer**. Die garagedeuropener reageer net op die **korrekte kode**, wat dit baie moeiliker maak vir iemand om ongemagtigde toegang tot die garage te verkry deur bloot ’n kode vas te lê.

### **Missing Link Attack**

Basies luister jy vir die knoppie en **neem jy die sein op terwyl die afstandbeheerder buite die toestel se reikafstand is** (byvoorbeeld die motor of garage). Dan beweeg jy na die toestel en **gebruik jy die vasgelegde kode om dit oop te maak**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> Opsetlike RF-inmenging is in baie jurisdiksies onwettig en kan stelsels wat vir veiligheid belangrik is, ontwrig. Voer jamming-toetse slegs in ’n afgeskermde, gemagtigde laboratorium en volgens die toepaslike radioregulasies uit.<sup>[[6]](#references)</sup>

’n Aanvaller kan **die sein naby die voertuig of ontvanger jam** sodat die ontvanger nie die kode kan dekodeer nie, die geblokkeerde uitsending afsonderlik vaslê, ophou jamming toepas en dan die vasgelegde kode weer speel.<sup>[[2]](#references)</sup>

Die slagoffer sal op ’n stadium die **sleutels gebruik om die motor te sluit**, maar teen daardie tyd sal die aanval **genoeg “close door”-kodes opgeneem het** wat hopelik weer uitgestuur kan word om die deur oop te maak (’n **frekwensieverandering kan nodig wees**, want daar is motors wat dieselfde kodes gebruik om oop en toe te sluit, maar vir albei opdragte op verskillende frekwensies luister).

> [!WARNING]
> **Jamming werk**, maar dit is opvallend: as die **persoon wat die motor sluit bloot die deure toets** om seker te maak hulle is gesluit, sal hulle agterkom dat die motor ontsluit is. Verder, as hulle van sulke aanvalle bewus is, kan hulle selfs agterkom dat die deure nooit die sluit-**geluid** gemaak het nie, of dat die motor se **ligte** nie geflits het toe hulle die ‘lock’-knoppie gedruk het nie.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Dit is ’n meer **stealth Jamming-tegniek**. Die aanvaller jam die sein sodat die slagoffer nie die deur kan sluit wanneer hulle dit probeer nie, maar die aanvaller **neem hierdie kode op**. Dan sal die slagoffer **weer probeer om die motor te sluit** deur die knoppie te druk, en die motor sal **hierdie tweede kode opneem**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Onmiddellik daarna kan die **aanvaller die eerste kode stuur** en die **motor sal sluit** (die slagoffer sal dink dat die tweede druk dit gesluit het). Dan sal die aanvaller die **tweede gesteelde kode kan stuur om** die motor oop te maak (met die aanname dat ’n **“close car”-kode ook gebruik kan word om dit oop te maak**). ’n Frekwensieverandering kan nodig wees (want daar is motors wat dieselfde kodes gebruik om oop en toe te sluit, maar vir albei opdragte op verskillende frekwensies luister).

Een RollJam-implementering benut die ontvanger se bandwydte: die jammer stuur naby genoeg aan die afstandbeheerder se draerfrekwensie uit om die voertuig se breër ontvanger te desensitiseer, terwyl die aanvaller se nouer ontvanger op die afstandbeheerder ingestel bly en steeds die sein kan opneem. Die presiese frekwensie-afwyking en bandwydte hang van die teikenhardeware af.<sup>[[2]](#references)</sup>

> [!WARNING]
> Ander implementerings wat in spesifikasies gesien is, toon dat die **rolling code ’n gedeelte** van die totale gestuurde kode is. D.w.s. die gestuurde kode is ’n **24-bis-sleutel**, waar die eerste **12 die rolling code is**, die **volgende 8 die opdrag is** (soos sluit of ontsluit), en die laaste 4 die **kontrolesom** is. Voertuie wat hierdie tipe implementeer, is ook inherent kwesbaar, aangesien die aanvaller bloot die rolling code-segment hoef te vervang om **enige rolling code op albei frekwensies te kan gebruik**.

> [!CAUTION]
> Let daarop dat as die slagoffer ’n derde kode stuur terwyl die aanvaller die eerste een stuur, die eerste en tweede kode ongeldig gemaak sal word.

### Alarm Sounding Jamming Attack

Tydens toetsing teen ’n aftermarket rolling code-stelsel wat in ’n motor geïnstalleer is, het **die onmiddellike stuur van dieselfde kode twee keer** die alarm en immobiliseerder **geaktiveer**, wat ’n unieke **denial of service**-geleentheid gebied het. Ironies genoeg was die manier om die alarm en immobiliseerder **te deaktiveer** om die **afstandbeheerder te druk**, wat ’n aanvaller die vermoë gee om **aanhoudend ’n DoS-aanval uit te voer**. Of kombineer hierdie aanval met die **vorige een om meer kodes te bekom**, aangesien die slagoffer die aanval so gou moontlik sal wil stop.<sup>[[2]](#references)</sup>

## References

- [1] [Flipper Zero-dokumentasie - Sub-GHz-frekwensies volgens streek](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Omseiling van Rolling Code-stelsels - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Ry dit soos jy dit gehack het (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Hoe om ’n motor te hack - RollJam-heruitvoering met YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [OpenSesame-bronkode](https://github.com/samyk/opensesame)
- [6] [FCC-handhawingsadvies - Handhawing teen Jammers](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
