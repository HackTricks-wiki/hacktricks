# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Deure

Garage deur oopmakers werk tipies op frekwensies in die 300-190 MHz reeks, met die mees algemene frekwensies wat 300 MHz, 310 MHz, 315 MHz, en 390 MHz is. Hierdie frekwensie reeks word algemeen gebruik vir garage deur oopmakers omdat dit minder oorvol is as ander frekwensie bande en minder geneig is om interferensie van ander toestelle te ervaar.

## Motor Deure

Meeste motor sleutelfobbe werk op **315 MHz of 433 MHz**. Dit is albei radiofrekwensies, en hulle word in 'n verskeidenheid van verskillende toepassings gebruik. Die hoof verskil tussen die twee frekwensies is dat 433 MHz 'n langer reeks het as 315 MHz. Dit beteken dat 433 MHz beter is vir toepassings wat 'n langer reeks vereis, soos afstandsleutel toegang.\
In Europa word 433.92MHz algemeen gebruik en in die VSA en Japan is dit die 315MHz.

## **Brute-force Aanval**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

As jy in plaas daarvan om elke kode 5 keer te stuur (gestuur soos dit om seker te maak die ontvanger dit ontvang) net een keer stuur, word die tyd verminder tot 6 minute:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

en as jy die **2 ms wag** periode tussen seine verwyder, kan jy die tyd **tot 3 minute verminder.**

Boonop, deur die De Bruijn Sequentie te gebruik (‘n manier om die aantal bits wat nodig is om al die potensiële binêre nommers te stuur te verminder) word hierdie **tyd net tot 8 sekondes verminder**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

'n Voorbeeld van hierdie aanval is geïmplementeer in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Die vereiste van **'n preamble sal die De Bruijn Sequentie** optimalisering vermy en **rolkode sal hierdie aanval voorkom** (onder die aanname dat die kode lank genoeg is om nie gebruteforceer te kan word nie).

## Sub-GHz Aanval

Om hierdie seine met Flipper Zero aan te val, kyk:

{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolkode Beskerming

Outomatiese garage deur oopmakers gebruik tipies 'n draadlose afstandbeheer om die garage deur te open en toe te maak. Die afstandbeheer **stuur 'n radiofrekwensie (RF) sein** na die garage deur oopmaker, wat die motor aktiveer om die deur te open of toe te maak.

Dit is moontlik vir iemand om 'n toestel bekend as 'n kodegrypper te gebruik om die RF sein te onderskep en dit vir later gebruik op te neem. Dit staan bekend as 'n **herhalingsaanval**. Om hierdie tipe aanval te voorkom, gebruik baie moderne garage deur oopmakers 'n meer veilige versleuteling metode bekend as 'n **rolkode** stelsel.

Die **RF sein word tipies oorgedra met 'n rolkode**, wat beteken dat die kode met elke gebruik verander. Dit maak dit **moeilik** vir iemand om die sein te **onderskep** en dit te **gebruik** om **ongemagtigde** toegang tot die garage te verkry.

In 'n rolkode stelsel het die afstandbeheer en die garage deur oopmaker 'n **gedeelde algoritme** wat **'n nuwe kode genereer** elke keer wanneer die afstandbeheer gebruik word. Die garage deur oopmaker sal slegs op die **korrekte kode** reageer, wat dit baie moeiliker maak vir iemand om ongemagtigde toegang tot die garage te verkry net deur 'n kode te vang.

### **Ontbrekende Kode Aanval**

Basies, jy luister vir die knoppie en **vang die sein terwyl die afstandbeheer buite bereik** van die toestel (sê die motor of garage). Jy beweeg dan na die toestel en **gebruik die gevangen kode om dit te open**.

### Volledige Kode Jamming Aanval

'n Aanvaller kan die **sein naby die voertuig of ontvanger** blokkeer sodat die **ontvanger nie eintlik die kode kan ‘hoor’ nie**, en sodra dit gebeur, kan jy eenvoudig die kode **vang en herhaal** wanneer jy opgehou het om te blokkeer.

Die slagoffer sal op 'n stadium die **sleutels gebruik om die motor te sluit**, maar dan sal die aanval **genoeg "sluit deur" kodes opgeneem het** wat hoopvol weer gestuur kan word om die deur te open (‘n **verandering van frekwensie mag nodig wees** aangesien daar motors is wat dieselfde kodes gebruik om te open en toe te maak maar na beide opdragte in verskillende frekwensies luister).

> [!WARNING]
> **Jamming werk**, maar dit is opmerklik as die **persoon wat die motor sluit eenvoudig die deure toets** om te verseker dat hulle gesluit is, sal hulle opgemerk dat die motor ontgrendel is. Boonop, as hulle bewus was van sulke aanvalle, kan hulle selfs luister na die feit dat die deure nooit die sluit **klank** gemaak het nie of die motor se **ligte** nooit geflits het toe hulle die ‘sluit’ knoppie gedruk het.

### **Kode Grabbing Aanval (ook bekend as ‘RollJam’)**

Dit is 'n meer **stealth Jamming tegniek**. Die aanvaller sal die sein blokkeer, sodat wanneer die slagoffer probeer om die deur te sluit, dit nie sal werk nie, maar die aanvaller sal **hierdie kode opneem**. Dan sal die slagoffer **weer probeer om die motor te sluit** deur die knoppie te druk en die motor sal **hierdie tweede kode opneem**.\
Onmiddellik daarna kan die **aanvaller die eerste kode stuur** en die **motor sal sluit** (die slagoffer sal dink die tweede druk het dit gesluit). Dan sal die aanvaller in staat wees om die **tweede gesteelde kode te stuur om** die motor te open (onder die aanname dat 'n **"sluit motor" kode ook gebruik kan word om dit te open**). 'n Verandering van frekwensie mag nodig wees (aangesien daar motors is wat dieselfde kodes gebruik om te open en toe te maak maar na beide opdragte in verskillende frekwensies luister).

Die aanvaller kan die motor ontvanger blokkeer en nie sy ontvanger nie, want as die motor ontvanger luister in byvoorbeeld 'n 1MHz breedband, sal die aanvaller nie die presiese frekwensie wat deur die afstandbeheer gebruik word blokkeer nie, maar **'n nabygeleë een in daardie spektrum** terwyl die **aanvaller se ontvanger in 'n kleiner reeks luister** waar hy die afstandbeheer sein kan **hoor sonder die blokkeer sein**.

> [!WARNING]
> Ander implementasies gesien in spesifikasies toon dat die **rolkode 'n gedeelte** van die totale kode wat gestuur word is. Dit wil sê die kode wat gestuur word is 'n **24-bis sleutel** waar die eerste **12 die rolkode** is, die **tweede 8 die opdrag** (soos sluit of ontgrendel) en die laaste 4 is die **kontrole som**. Voertuie wat hierdie tipe implementeer is ook natuurlik kwesbaar aangesien die aanvaller bloot die rolkode segment moet vervang om enige rolkode op beide frekwensies te **gebruik**.

> [!CAUTION]
> Let daarop dat as die slagoffer 'n derde kode stuur terwyl die aanvaller die eerste een stuur, die eerste en tweede kode ongeldig sal wees.

### Alarm Klank Jamming Aanval

Toets teen 'n naverkoop rolkode stelsel wat op 'n motor geïnstalleer is, **die stuur van dieselfde kode twee keer** het onmiddellik die alarm en immobiliseerder geaktiveer wat 'n unieke **ontkenning van diens** geleentheid bied. Ironies was die middel om die **alarm** en immobiliseerder te **deaktiveer** om die **afstandbeheer** te **druk**, wat 'n aanvaller die vermoë gee om **deurlopend DoS aanvalle** uit te voer. Of meng hierdie aanval met die **vorige een om meer kodes te verkry** aangesien die slagoffer graag die aanval so gou as moontlik wil stop.

## Verwysings

- [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
- [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
