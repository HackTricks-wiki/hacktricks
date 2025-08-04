# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes in die geheue van 'n lopende speletjie gestoor word en om hulle te verander.\
Wanneer jy dit aflaai en uitvoer, word jy **aanbied** met 'n **tutorial** oor hoe om die hulpmiddel te gebruik. As jy wil leer hoe om die hulpmiddel te gebruik, word dit sterk aanbeveel om dit te voltooi.

## Wat soek jy?

![](<../../images/image (762).png>)

Hierdie hulpmiddel is baie nuttig om te vind **waar 'n waarde** (gewoonlik 'n nommer) **in die geheue** van 'n program gestoor word.\
**Gewoonlik** word nommers in **4bytes** vorm gestoor, maar jy kan hulle ook in **double** of **float** formate vind, of jy mag dalk iets **anders as 'n nommer** wil soek. Om hierdie rede moet jy seker wees dat jy **kies** wat jy wil **soek**:

![](<../../images/image (324).png>)

Jy kan ook **verskillende** tipes **soeke** aandui:

![](<../../images/image (311).png>)

Jy kan ook die boks merk om die **speletjie te stop terwyl jy die geheue skandeer**:

![](<../../images/image (1052).png>)

### Hotkeys

In _**Edit --> Settings --> Hotkeys**_ kan jy verskillende **hotkeys** vir verskillende doeleindes instel, soos om die **speletjie te stop** (wat baie nuttig is as jy op 'n stadium die geheue wil skandeer). Ander opsies is beskikbaar:

![](<../../images/image (864).png>)

## Die waarde verander

Sodra jy **gevind** het waar die **waarde** is wat jy **soek** (meer oor hierdie in die volgende stappe) kan jy dit **verander** deur dit dubbel te klik, en dan dubbel te klik op sy waarde:

![](<../../images/image (563).png>)

En uiteindelik **merk die vink** om die verandering in die geheue te laat plaasvind:

![](<../../images/image (385).png>)

Die **verandering** aan die **geheue** sal onmiddellik **toegepas** word (let daarop dat totdat die speletjie hierdie waarde weer gebruik, die waarde **nie in die speletjie opgedateer sal word**).

## Soek die waarde

So, ons gaan veronderstel dat daar 'n belangrike waarde is (soos die lewe van jou gebruiker) wat jy wil verbeter, en jy soek hierdie waarde in die geheue)

### Deur 'n bekende verandering

Veronderstel jy soek die waarde 100, jy **voer 'n skandering uit** wat na daardie waarde soek en jy vind baie ooreenkomste:

![](<../../images/image (108).png>)

Dan, jy doen iets sodat die **waarde verander**, en jy **stop** die speletjie en **voers** 'n **volgende skandering**:

![](<../../images/image (684).png>)

Cheat Engine sal soek na die **waardes** wat **van 100 na die nuwe waarde gegaan het**. Geluk, jy **het gevind** die **adres** van die waarde waarna jy gesoek het, jy kan dit nou verander.\
_As jy steeds verskeie waardes het, doen iets om daardie waarde weer te verander, en voer 'n ander "volgende skandering" uit om die adresse te filter._

### Onbekende Waarde, bekende verandering

In die scenario waar jy **nie die waarde weet nie** maar jy weet **hoe om dit te laat verander** (en selfs die waarde van die verandering) kan jy jou nommer soek.

So, begin deur 'n skandering van die tipe "**Onbekende aanvanklike waarde**" uit te voer:

![](<../../images/image (890).png>)

Dan, laat die waarde verander, dui **hoe** die **waarde** **verander** het (in my geval is dit met 1 verminder) en voer 'n **volgende skandering** uit:

![](<../../images/image (371).png>)

Jy sal **alle waardes wat op die geselekteerde manier gewysig is** voorgelê word:

![](<../../images/image (569).png>)

Sodra jy jou waarde gevind het, kan jy dit verander.

Let daarop dat daar 'n **groot aantal moontlike veranderinge** is en jy kan hierdie **stappe soveel keer as wat jy wil** herhaal om die resultate te filter:

![](<../../images/image (574).png>)

### Willekeurige Geheueadres - Vind die kode

Tot nou toe het ons geleer hoe om 'n adres te vind wat 'n waarde stoor, maar dit is hoogs waarskynlik dat in **verskillende uitvoerings van die speletjie daardie adres in verskillende plekke van die geheue is**. So kom ons vind uit hoe om daardie adres altyd te vind.

Gebruik sommige van die genoem truuks, vind die adres waar jou huidige speletjie die belangrike waarde stoor. Dan (stop die speletjie as jy wil) doen 'n **regsklik** op die gevonde **adres** en kies "**Vind uit wat hierdie adres benader**" of "**Vind uit wat na hierdie adres skryf**":

![](<../../images/image (1067).png>)

Die **eerste opsie** is nuttig om te weet watter **dele** van die **kode** hierdie **adres** **gebruik** (wat nuttig is vir meer dinge soos **om te weet waar jy die kode** van die speletjie kan verander).\
Die **tweede opsie** is meer **spesifiek**, en sal meer nuttig wees in hierdie geval aangesien ons belangstel om te weet **van waar hierdie waarde geskryf word**.

Sodra jy een van daardie opsies gekies het, sal die **debugger** aan die program **gekoppel** word en 'n nuwe **leë venster** sal verskyn. Nou, **speel** die **speletjie** en **verander** daardie **waarde** (sonder om die speletjie te herbegin). Die **venster** moet **gevul** wees met die **adresse** wat die **waarde** **verander**:

![](<../../images/image (91).png>)

Nou dat jy die adres gevind het wat die waarde verander, kan jy die **kode na jou goeddunke verander** (Cheat Engine laat jou toe om dit vinnig vir NOPs te verander):

![](<../../images/image (1057).png>)

So, jy kan dit nou verander sodat die kode jou nommer nie beïnvloed nie, of altyd op 'n positiewe manier beïnvloed.

### Willekeurige Geheueadres - Vind die pointer

Volg die vorige stappe, vind waar die waarde wat jy belangstel in is. Dan, gebruik "**Vind uit wat na hierdie adres skryf**" om uit te vind watter adres hierdie waarde skryf en dubbelklik daarop om die disassembly-weergave te kry:

![](<../../images/image (1039).png>)

Dan, voer 'n nuwe skandering uit **soek na die hex waarde tussen "\[]"** (die waarde van $edx in hierdie geval):

![](<../../images/image (994).png>)

(_As verskeie verskyn, het jy gewoonlik die kleinste adres een nodig_)\
Nou, het ons **die pointer gevind wat die waarde wat ons belangstel in sal verander**.

Klik op "**Voeg adres handmatig by**":

![](<../../images/image (990).png>)

Nou, klik op die "Pointer" vink en voeg die gevonde adres in die teksvak in (in hierdie scenario was die gevonde adres in die vorige beeld "Tutorial-i386.exe"+2426B0):

![](<../../images/image (392).png>)

(let op hoe die eerste "Adres" outomaties ingevul word vanaf die pointer adres wat jy invoer)

Klik OK en 'n nuwe pointer sal geskep word:

![](<../../images/image (308).png>)

Nou, elke keer as jy daardie waarde verander, **verander jy die belangrike waarde selfs al is die geheueadres waar die waarde is anders.**

### Kode-inspuiting

Kode-inspuiting is 'n tegniek waar jy 'n stuk kode in die teikenproses inspuit, en dan die uitvoering van kode herlei om deur jou eie geskryf kode te gaan (soos om jou punte te gee in plaas van om hulle af te trek).

So, verbeel jou jy het die adres gevind wat 1 van die lewe van jou speler aftrek:

![](<../../images/image (203).png>)

Klik op Toon disassembler om die **disassemble kode** te kry.\
Dan, klik **CTRL+a** om die Auto assemble venster te ontbied en kies _**Template --> Kode-inspuiting**_

![](<../../images/image (902).png>)

Vul die **adres van die instruksie wat jy wil verander** (dit word gewoonlik outomaties ingevul):

![](<../../images/image (744).png>)

' n Sjabloon sal gegenereer word:

![](<../../images/image (944).png>)

So, voeg jou nuwe assembly kode in die "**newmem**" afdeling in en verwyder die oorspronklike kode uit die "**originalcode**" as jy nie wil hê dit moet uitgevoer word nie. In hierdie voorbeeld sal die ingespuite kode 2 punte byvoeg in plaas van om 1 af te trek:

![](<../../images/image (521).png>)

**Klik op voer uit en so aan en jou kode moet in die program ingespuit word wat die gedrag van die funksionaliteit verander!**

## Gevorderde funksies in Cheat Engine 7.x (2023-2025)

Cheat Engine het voortgegaan om te ontwikkel sedert weergawe 7.0 en verskeie kwaliteit-van-lewe en *offensiewe-omgekeerde* funksies is bygevoeg wat uiters handig is wanneer moderne sagteware (en nie net speletjies nie!) geanaliseer word. Hieronder is 'n **baie gekondenseerde veldgids** na die toevoegings wat jy waarskynlik tydens rooi-span/CTF werk sal gebruik.

### Pointer Scanner 2 verbeterings
* `Pointers moet eindig met spesifieke offsets` en die nuwe **Deviation** skuif (≥7.4) verminder grootliks vals positiewe wanneer jy weer skandeer na 'n opdatering. Gebruik dit saam met multi-map vergelyking (`.PTR` → *Vergelyk resultate met ander gestoor pointer kaart*) om 'n **enkele veerkragtige basis-pointer** in net 'n paar minute te verkry.
* Groot-filter sneltoets: na die eerste skandering druk `Ctrl+A → Space` om alles te merk, dan `Ctrl+I` (omgekeerd) om adresse wat die her-skanse misluk het, te deselecteer.

### Ultimap 3 – Intel PT opsporing
*Vanaf 7.5 is die ou Ultimap weer geïmplementeer bo-op **Intel Processor-Trace (IPT)**. Dit beteken jy kan nou *elke* tak wat die teiken neem **sonder om enkel-stap** (gebruikersmodus slegs, dit sal nie die meeste anti-debug gadgets aktiveer).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Na 'n paar sekondes stop die opname en **regsklik → Stoor uitvoeringslys na lêer**. Kombineer takadresse met 'n `Vind uit watter adresse hierdie instruksie benader` sessie om hoë-frekwensie speletjie-logika hotspots baie vinnig te lokaliseer.

### 1-byte `jmp` / auto-patch templates
Weergawe 7.5 het 'n *een-byte* JMP stub (0xEB) bekendgestel wat 'n SEH handler installeer en 'n INT3 op die oorspronklike plek plaas. Dit word outomaties gegenereer wanneer jy **Auto Assembler → Template → Code Injection** op instruksies gebruik wat nie met 'n 5-byte relatiewe sprong gepatch kan word nie. Dit maak “stywe” haakies moontlik binne gepakte of grootte-beperkte roetines.

### Kernel-niveau stealth met DBVM (AMD & Intel)
*DBVM* is CE se ingeboude Type-2 hypervisor. Onlangs geboue het uiteindelik **AMD-V/SVM ondersteuning** bygevoeg sodat jy `Driver → Laai DBVM` op Ryzen/EPYC gasheer kan uitvoer. DBVM laat jou toe om:
1. Hardeware breekpunte te skep wat onsigbaar is vir Ring-3/anti-debug kontroles.
2. Lees/skryf na bladsybare of beskermde kerngeheue areas selfs wanneer die gebruikersmodus bestuurder gedeaktiveer is.
3. VM-EXIT-loos tyd-aanval omseilings uit te voer (bv. vra `rdtsc` van die hypervisor).

**Wenk:** DBVM sal weier om te laai wanneer HVCI/Geheue-Integriteit geaktiveer is op Windows 11 → skakel dit af of begin 'n toegewyde VM-gasheer. 

### Afgeleë / kruis-platform foutopsporing met **ceserver**
CE verskaf nou 'n volledige herskrywing van *ceserver* en kan oor TCP aan **Linux, Android, macOS & iOS** teikens koppel. 'n Gewilde fork integreer *Frida* om dinamiese instrumentasie met CE se GUI te kombineer – ideaal wanneer jy Unity of Unreal speletjies wat op 'n telefoon loop, moet patch.
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
For the Frida bridge see `bb33bb/frida-ceserver` on GitHub.

### Ander noemenswaardige goedere
* **Patch Scanner** (MemView → Tools) – detecteer onverwagte kode veranderinge in uitvoerbare afdelings; handig vir malware analise.
* **Structure Dissector 2** – sleep-'n-adres → `Ctrl+D`, dan *Raai velde* om C-strukture outomaties te evalueer.
* **.NET & Mono Dissector** – verbeterde Unity speletjie ondersteuning; bel metode direk vanaf die CE Lua-konsol.
* **Big-Endian pasgemaakte tipes** – omgekeerde byte volgorde skandering/redigering (nuttig vir konsol emulators en netwerk pakket buffers).
* **Autosave & oortjies** vir AutoAssembler/Lua vensters, plus `reassemble()` vir multi-lyn instruksie herskrywing.

### Installasie & OPSEC notas (2024-2025)
* Die amptelike installeerder is verpak met InnoSetup **ad-aanbiedinge** (`RAV` ens.). **Klik altyd op *Weier*** *of compileer vanaf bron* om PUPs te vermy. AVs sal steeds `cheatengine.exe` as 'n *HackTool* merk, wat verwag word.
* Moderne anti-cheat bestuurders (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) detecteer CE se venster klas selfs wanneer dit hernoem is. Voer jou omgekeerde kopie **binne 'n weggooibare VM** of nadat jy netwerk speel gedeaktiveer het.
* As jy net gebruikersmodus toegang nodig het, kies **`Settings → Extra → Kernel mode debug = off`** om te verhoed dat CE se ongetekende bestuurder gelaai word wat BSOD op Windows 11 24H2 Secure-Boot mag veroorsaak.

---

## **Verwysings**

- [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- **Cheat Engine tutorial, voltooi dit om te leer hoe om met Cheat Engine te begin**

{{#include ../../banners/hacktricks-training.md}}
