# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes binne die geheue van 'n lopende speletjie gestoor word en om hulle te verander.\
Wanneer jy dit aflaai en uitvoer, word jy **aanbied** met 'n **tutorial** oor hoe om die hulpmiddel te gebruik. As jy wil leer hoe om die hulpmiddel te gebruik, word dit sterk aanbeveel om dit te voltooi.

## Wat soek jy?

![](<../../images/image (762).png>)

Hierdie hulpmiddel is baie nuttig om te vind **waar 'n waarde** (gewoonlik 'n nommer) **in die geheue** van 'n program gestoor word.\
**Gewoonlik word nommers** in **4bytes** vorm gestoor, maar jy kan hulle ook in **double** of **float** formate vind, of jy mag dalk iets **anders as 'n nommer** wil soek. Om hierdie rede moet jy seker wees dat jy **kies** wat jy wil **soek**:

![](<../../images/image (324).png>)

Jy kan ook **verskillende** tipes **soeke** aandui:

![](<../../images/image (311).png>)

Jy kan ook die boks merk om **die speletjie te stop terwyl jy die geheue skandeer**:

![](<../../images/image (1052).png>)

### Hotkeys

In _**Edit --> Settings --> Hotkeys**_ kan jy verskillende **hotkeys** vir verskillende doeleindes stel, soos **om die speletjie te stop** (wat baie nuttig is as jy op 'n stadium die geheue wil skandeer). Ander opsies is beskikbaar:

![](<../../images/image (864).png>)

## Waarde verander

Sodra jy **gevind** het waar die **waarde** wat jy **soek** is (meer oor hierdie in die volgende stappe), kan jy dit **verander** deur dit dubbel te klik, en dan dubbel te klik op sy waarde:

![](<../../images/image (563).png>)

En uiteindelik **merk die vinkie** om die verandering in die geheue te laat plaasvind:

![](<../../images/image (385).png>)

Die **verandering** aan die **geheue** sal onmiddellik **toegepas** word (let daarop dat totdat die speletjie hierdie waarde nie weer gebruik nie, die waarde **nie in die speletjie opgedateer sal word**).

## Waarde soek

So, ons gaan veronderstel dat daar 'n belangrike waarde is (soos die lewe van jou gebruiker) wat jy wil verbeter, en jy soek hierdie waarde in die geheue)

### Deur 'n bekende verandering

Veronderstel jy soek die waarde 100, jy **voerende 'n skandering** om daardie waarde te soek en jy vind baie ooreenkomste:

![](<../../images/image (108).png>)

Dan, doen jy iets sodat **die waarde verander**, en jy **stop** die speletjie en **voerende** 'n **volgende skandering**:

![](<../../images/image (684).png>)

Cheat Engine sal soek na die **waardes** wat **van 100 na die nuwe waarde gegaan het**. Geluk, jy **gevind** die **adres** van die waarde waarna jy gesoek het, jy kan dit nou verander.\
&#xNAN;_&#x49;f jy steeds verskeie waardes het, doen iets om daardie waarde weer te verander, en voer 'n ander "volgende skandering" uit om die adresse te filter._

### Onbekende waarde, bekende verandering

In die scenario waar jy **nie die waarde weet nie** maar jy weet **hoe om dit te laat verander** (en selfs die waarde van die verandering) kan jy jou nommer soek.

So, begin deur 'n skandering van tipe "**Onbekende aanvanklike waarde**" uit te voer:

![](<../../images/image (890).png>)

Dan, laat die waarde verander, dui **hoe** die **waarde** **verander** het (in my geval is dit met 1 verminder) en voer 'n **volgende skandering** uit:

![](<../../images/image (371).png>)

Jy sal **alle waardes wat op die geselekteerde manier gewysig is** voorgestel word:

![](<../../images/image (569).png>)

Sodra jy jou waarde gevind het, kan jy dit verander.

Let daarop dat daar 'n **baie moontlike veranderinge** is en jy kan hierdie **stappe soveel keer as wat jy wil** doen om die resultate te filter:

![](<../../images/image (574).png>)

### Willekeurige geheue adres - Vind die kode

Tot nou toe het ons geleer hoe om 'n adres te vind wat 'n waarde stoor, maar dit is hoogs waarskynlik dat in **verskillende uitvoerings van die speletjie daardie adres in verskillende plekke van die geheue is**. So kom ons vind uit hoe om daardie adres altyd te vind.

Gebruik sommige van die genoem truuks, vind die adres waar jou huidige speletjie die belangrike waarde stoor. Dan (stop die speletjie as jy wil) doen 'n **regsklik** op die gevonde **adres** en kies "**Vind uit wat hierdie adres benader**" of "**Vind uit wat na hierdie adres skryf**":

![](<../../images/image (1067).png>)

Die **eerste opsie** is nuttig om te weet watter **dele** van die **kode** hierdie **adres** **gebruik** (wat nuttig is vir meer dinge soos **om te weet waar jy die kode** van die speletjie kan verander).\
Die **tweede opsie** is meer **spesifiek**, en sal meer nuttig wees in hierdie geval aangesien ons belangstel om te weet **van waar hierdie waarde geskryf word**.

Sodra jy een van daardie opsies gekies het, sal die **debugger** aan die program **gekoppel** word en 'n nuwe **leë venster** sal verskyn. Nou, **speel** die **speletjie** en **verander** daardie **waarde** (sonder om die speletjie te herbegin). Die **venster** moet **gevul** wees met die **adresse** wat die **waarde** **verander**:

![](<../../images/image (91).png>)

Nou dat jy die adres gevind het wat die waarde verander, kan jy **die kode na jou goeddunke verander** (Cheat Engine laat jou toe om dit vinnig vir NOPs te verander):

![](<../../images/image (1057).png>)

So, jy kan dit nou verander sodat die kode nie jou nommer beïnvloed nie, of altyd op 'n positiewe manier beïnvloed.

### Willekeurige geheue adres - Vind die pointer

Volg die vorige stappe, vind waar die waarde wat jy belangstel in is. Dan, gebruik "**Vind uit wat na hierdie adres skryf**" om uit te vind watter adres hierdie waarde skryf en dubbelklik daarop om die disassembly-weergave te kry:

![](<../../images/image (1039).png>)

Dan, voer 'n nuwe skandering uit **soek na die hex waarde tussen "\[]"** (die waarde van $edx in hierdie geval):

![](<../../images/image (994).png>)

(_As verskeie verskyn, het jy gewoonlik die kleinste adres een nodig_)\
Nou, het ons **die pointer gevind wat die waarde wat ons belangstel in sal verander**.

Klik op "**Voeg adres handmatig by**":

![](<../../images/image (990).png>)

Nou, klik op die "Pointer" vinkie en voeg die gevonde adres in die tekskas in (in hierdie scenario was die gevonde adres in die vorige beeld "Tutorial-i386.exe"+2426B0):

![](<../../images/image (392).png>)

(Noteer hoe die eerste "Adres" outomaties ingevul word vanaf die pointer adres wat jy invoer)

Klik OK en 'n nuwe pointer sal geskep word:

![](<../../images/image (308).png>)

Nou, elke keer as jy daardie waarde verander, verander jy **die belangrike waarde selfs al is die geheue adres waar die waarde is anders.**

### Kode-inspuiting

Kode-inspuiting is 'n tegniek waar jy 'n stuk kode in die teikenproses inspuit, en dan die uitvoering van kode herlei om deur jou eie geskryf kode te gaan (soos om jou punte te gee in plaas van om hulle af te trek).

So, verbeel jou jy het die adres gevind wat 1 van die lewe van jou speler aftrek:

![](<../../images/image (203).png>)

Klik op Toon disassembler om die **disassemble kode** te kry.\
Dan, klik **CTRL+a** om die Auto assemble venster aan te roep en kies _**Template --> Kode-inspuiting**_

![](<../../images/image (902).png>)

Vul die **adres van die instruksie wat jy wil verander** (dit word gewoonlik outomaties ingevul):

![](<../../images/image (744).png>)

'n Sjabloon sal gegenereer word:

![](<../../images/image (944).png>)

So, voeg jou nuwe assembly kode in die "**newmem**" afdeling in en verwyder die oorspronklike kode uit die "**originalcode**" as jy nie wil hê dit moet uitgevoer word\*\*.\*\* In hierdie voorbeeld sal die ingespuite kode 2 punte byvoeg in plaas van om 1 af te trek:

![](<../../images/image (521).png>)

**Klik op voer uit en so aan en jou kode behoort in die program ingespuit te wees wat die gedrag van die funksionaliteit verander!**

## **Verwysings**

- **Cheat Engine tutorial, voltooi dit om te leer hoe om met Cheat Engine te begin**

{{#include ../../banners/hacktricks-training.md}}
