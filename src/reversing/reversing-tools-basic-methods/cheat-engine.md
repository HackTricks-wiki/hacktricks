# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes binne die geheue van 'n lopende game gestoor word en dit te verander.\
Wanneer jy dit aflaai en uitvoer, word jy met 'n **tutorial** oor hoe om die hulpmiddel te gebruik, **aangebied**. As jy wil leer hoe om die hulpmiddel te gebruik, word dit sterk aanbeveel dat jy dit voltooi.

## Waarna soek jy?

![Cheat Engine - Waarna soek jy?: Waarna soek jy?](<../../images/image (762).png>)

Hierdie hulpmiddel is baie nuttig om te vind **waar 'n waarde** (gewoonlik 'n getal) **in die geheue** van 'n program gestoor word.\
**Getalle** word **gewoonlik** in **4bytes**-formaat gestoor, maar jy kan hulle ook in **double**- of **float**-formate vind, of jy wil dalk na iets **anders as 'n getal** soek. Daarom moet jy seker maak dat jy **kies** waarna jy wil **soek**:

![Cheat Engine - Waarna soek jy?: Getalle word gewoonlik in 4bytes-formaat gestoor, maar jy kan hulle ook in double- of float-formate vind, of jy wil dalk na iets anders soek...](<../../images/image (324).png>)

Jy kan ook **verskillende** tipes **soektogte** aandui:

![Cheat Engine - Waarna soek jy?: Jy kan ook verskillende tipes soektogte aandui](<../../images/image (311).png>)

Jy kan ook die blokkie merk om die **game te stop terwyl die geheue geskandeer word**:

![Cheat Engine - Waarna soek jy?: Jy kan ook die blokkie merk om die game te stop terwyl die geheue geskandeer word](<../../images/image (1052).png>)

### Sneltoetse

In _**Edit --> Settings --> Hotkeys**_ kan jy verskillende **sneltoetse** vir verskillende doeleindes stel, soos om die **game** te **stop** (wat baie nuttig is as jy op 'n stadium die geheue wil skandeer). Ander opsies is beskikbaar:

![Waarna soek jy? - Sneltoetse: In Edit -- Settings -- Hotkeys kan jy verskillende sneltoetse vir verskillende doeleindes stel, soos om die game te stop (wat baie nuttig is as jy op 'n stadium...](<../../images/image (864).png>)

## Wysig die waarde

Sodra jy **gevind** het waar die **waarde** waarna jy **soek**, is (meer hieroor in die volgende stappe), kan jy dit **wysig** deur daarop te dubbelklik en dan op die waarde daarvan te dubbelklik:

![Sneltoetse - Wysig die waarde: Sodra jy gevind het waar die waarde waarna jy soek, is (meer hieroor in die volgende stappe), kan jy dit wysig deur daarop te dubbelklik en dan op...](<../../images/image (563).png>)

En laastens deur die **merkblokkie** te **merk** om die wysiging in die geheue toe te pas:

![Sneltoetse - Wysig die waarde: En laastens deur die merkblokkie te merk om die wysiging in die geheue toe te pas](<../../images/image (385).png>)

Die **verandering** aan die **geheue** sal onmiddellik **toegepas** word (let daarop dat die waarde **nie in die game opgedateer sal word** totdat die game hierdie waarde weer gebruik nie).

## Soek die waarde

Ons gaan dus aanvaar dat daar 'n belangrike waarde is (soos die lewe van jou user) wat jy wil verbeter, en dat jy hierdie waarde in die geheue soek)

### Deur 'n bekende verandering

Gestel jy soek die waarde 100, **voer jy 'n scan uit** vir daardie waarde en vind jy baie ooreenstemmings:

![Soek die waarde - Deur 'n bekende verandering: Gestel jy soek die waarde 100, voer jy 'n scan uit vir daardie waarde en vind jy baie ooreenstemmings](<../../images/image (108).png>)

Dan doen jy iets sodat die **waarde verander**, en **stop** jy die game en **voer** jy 'n **volgende scan** uit:

![Soek die waarde - Deur 'n bekende verandering: Dan doen jy iets sodat die waarde verander, en stop jy die game en voer jy 'n volgende scan uit](<../../images/image (684).png>)

Cheat Engine sal soek na die **waardes** wat **van 100 na die nuwe waarde verander het**. Baie geluk, jy het die **adres** van die waarde waarna jy gesoek het, **gevind**; jy kan dit nou wysig.\
_As jy steeds verskeie waardes het, doen iets om daardie waarde weer te verander, en voer nog 'n "next scan" uit om die adresse te filter._

### Onbekende waarde, bekende verandering

In die scenario waar jy **nie die waarde ken nie**, maar jy weet **hoe om dit te laat verander** (en selfs wat die verandering se waarde is), kan jy na jou getal soek.

Begin dus deur 'n scan van die tipe "**Unknown initial value**" uit te voer:

![Deur 'n bekende verandering - Onbekende waarde, bekende verandering: Begin dus deur 'n scan van die tipe " Unknown initial value " uit te voer](<../../images/image (890).png>)

Laat dan die waarde verander, dui aan **hoe** die **waarde** **verander het** (in my geval is dit met 1 verminder) en voer 'n **volgende scan** uit:

![Deur 'n bekende verandering - Onbekende waarde, bekende verandering: Laat dan die waarde verander, dui aan hoe die waarde verander het (in my geval is dit met 1 verminder) en voer 'n volgende scan uit](<../../images/image (371).png>)

Jy sal **al die waardes wat op die gekose manier gewysig is**, aangebied word:

![Deur 'n bekende verandering - Onbekende waarde, bekende verandering: Jy sal al die waardes wat op die gekose manier gewysig is, aangebied word](<../../images/image (569).png>)

Sodra jy jou waarde gevind het, kan jy dit wysig.

Let daarop dat daar **baie moontlike veranderinge** is en dat jy hierdie **stappe soveel keer as wat jy wil, kan uitvoer** om die resultate te filter:

![Deur 'n bekende verandering - Onbekende waarde, bekende verandering: Let daarop dat daar baie moontlike veranderinge is en dat jy hierdie stappe soveel keer as wat jy wil, kan uitvoer om die resultate te filter](<../../images/image (574).png>)

### Ewekansige geheue-adres - Vind die code

Tot dusver het ons geleer hoe om 'n adres te vind wat 'n waarde stoor, maar dit is hoogs waarskynlik dat die adres **tydens verskillende uitvoerings van die game op verskillende plekke in die geheue sal wees**. Kom ons vind dus uit hoe om altyd daardie adres te vind.

Gebruik sommige van die genoemde truuks om die adres te vind waar jou huidige game die belangrike waarde stoor. Doen dan (stop die game indien jy wil) 'n **regsklik** op die gevonde **adres** en kies "**Find out what accesses this address**" of "**Find out what writes to this address**":

![Onbekende waarde, bekende verandering - Ewekansige geheue-adres - Vind die code: Gebruik sommige van die genoemde truuks om die adres te vind waar jou huidige game die belangrike waarde stoor. Doen dan...](<../../images/image (1067).png>)

Die **eerste opsie** is nuttig om te weet watter **dele** van die **code** hierdie **adres gebruik** (wat nuttig is vir ander dinge, soos om te weet **waar jy die game se code kan wysig**).\
Die **tweede opsie** is meer **spesifiek** en sal in hierdie geval nuttiger wees, aangesien ons wil weet **waarvandaan hierdie waarde geskryf word**.

Sodra jy een van hierdie opsies gekies het, sal die **debugger** aan die program **gekoppel** word en 'n nuwe **leë venster** sal verskyn. **Speel** nou die **game** en **wysig** daardie **waarde** (sonder om die game te herbegin). Die **venster** behoort gevul te word met die **adresse** wat die **waarde wysig**:

![Onbekende waarde, bekende verandering - Ewekansige geheue-adres - Vind die code: Sodra jy een van hierdie opsies gekies het, sal die debugger aan die program gekoppel word en 'n nuwe leë venster...](<../../images/image (91).png>)

Noudat jy die adres gevind het wat die waarde wysig, kan jy die **code na goeddunke wysig** (Cheat Engine laat jou toe om dit baie vinnig na NOPs te wysig):

![Onbekende waarde, bekende verandering - Ewekansige geheue-adres - Vind die code: Noudat jy die adres gevind het wat die waarde wysig, kan jy die code na goeddunke wysig (Cheat Engine...](<../../images/image (1057).png>)

Jy kan dit nou wysig sodat die code nie jou getal sal beïnvloed nie, of dit altyd op 'n positiewe manier sal beïnvloed.

### Ewekansige geheue-adres - Vind die pointer

Volg die vorige stappe en vind waar die waarde waarin jy belangstel, is. Gebruik dan "**Find out what writes to this address**" om uit te vind watter adres hierdie waarde skryf, en dubbelklik daarop om die disassembly-aansig te verkry:

![Ewekansige geheue-adres - Vind die code - Ewekansige geheue-adres - Vind die pointer: Volg die vorige stappe en vind waar die waarde waarin jy belangstel, is. Gebruik dan " Find out...](<../../images/image (1039).png>)

Voer dan 'n nuwe scan uit en **soek na die hex-waarde tussen "\[]"** (die waarde van $edx in hierdie geval):

![Ewekansige geheue-adres - Vind die code - Ewekansige geheue-adres - Vind die pointer: Voer dan 'n nuwe scan uit en soek na die hex-waarde tussen " ()" (die waarde van $edx in hierdie geval)](<../../images/image (994).png>)

(_As verskeie verskyn, benodig jy gewoonlik die een met die kleinste adres_)\
Ons het nou **die pointer gevind wat die waarde waarin ons belangstel, sal wysig**.

Klik op "**Add Address Manually**":

![Ewekansige geheue-adres - Vind die code - Ewekansige geheue-adres - Vind die pointer: Klik op " Add Address Manually "](<../../images/image (990).png>)

Klik nou op die "Pointer"-merkblokkie en voeg die gevonde adres in die teksblokkie by (in hierdie scenario was die gevonde adres in die vorige afbeelding "Tutorial-i386.exe"+2426B0):

![Ewekansige geheue-adres - Vind die code - Ewekansige geheue-adres - Vind die pointer: Klik nou op die "Pointer"-merkblokkie en voeg die gevonde adres in die teksblokkie by (in hierdie scenario,...](<../../images/image (392).png>)

(Let op hoe die eerste "Address" outomaties ingevul word met die pointer-adres wat jy invoer)

Klik op OK en 'n nuwe pointer sal geskep word:

![Ewekansige geheue-adres - Vind die code - Ewekansige geheue-adres - Vind die pointer: Klik op OK en 'n nuwe pointer sal geskep word](<../../images/image (308).png>)

Nou, elke keer wanneer jy daardie waarde wysig, **wysig jy die belangrike waarde, selfs al verskil die geheue-adres waar die waarde is.**

### Code Injection

Code injection is 'n tegniek waar jy 'n stuk code in die teikenproses inject, en dan die uitvoering van die code herlei sodat dit deur jou eie geskrewe code gaan (soos om vir jou punte te gee in plaas daarvan om dit af te trek).

Gestel dus jy het die adres gevind wat 1 van jou speler se lewe aftrek:

![Ewekansige geheue-adres - Vind die pointer - Code Injection: Gestel dus jy het die adres gevind wat 1 van jou speler se lewe aftrek](<../../images/image (203).png>)

Klik op Show disassembler om die **disassembled code** te verkry.\
Klik dan **CTRL+a** om die Auto assemble-venster oop te maak en kies _**Template --> Code Injection**_

![Ewekansige geheue-adres - Vind die pointer - Code Injection: Klik dan CTRL+a om die Auto assemble-venster oop te maak en kies Template -- Code Injection](<../../images/image (902).png>)

Vul die **adres van die instruksie wat jy wil wysig** in (dit word gewoonlik outomaties ingevul):

![Ewekansige geheue-adres - Vind die pointer - Code Injection: Vul die adres van die instruksie wat jy wil wysig in (dit word gewoonlik outomaties ingevul)](<../../images/image (744).png>)

'n Template sal gegenereer word:

![Ewekansige geheue-adres - Vind die pointer - Code Injection: 'n Template sal gegenereer word](<../../images/image (944).png>)

Voeg dus jou nuwe assembly-code in die "**newmem**"-afdeling in en verwyder die oorspronklike code uit "**originalcode**" as jy nie wil hê dit moet uitgevoer word nie**.** In hierdie voorbeeld sal die injected code 2 punte byvoeg in plaas daarvan om 1 af te trek:

![Ewekansige geheue-adres - Vind die pointer - Code Injection: Voeg dus jou nuwe assembly-code in die " newmem "-afdeling in en verwyder die oorspronklike code uit die " originalcode " as jy...](<../../images/image (521).png>)

**Klik op execute en so aan, en jou code behoort in die program geïnject te word, wat die gedrag van die funksionaliteit verander!**

## Gevorderde funksies in Cheat Engine 7.x (2023-2025)

Cheat Engine het sedert weergawe 7.0 voortgegaan om te ontwikkel, en verskeie *offensive-reversing*-funksies en verbeterings aan gebruiksgemak is bygevoeg wat uiters handig is wanneer moderne sagteware (en nie net games nie!) ontleed word. Hieronder is 'n **baie bondige veldgids** tot die byvoegings wat jy waarskynlik tydens red-team/CTF-werk sal gebruik.<sup>[[1]](#references)</sup>

### Pointer Scanner 2-verbeterings
* `Pointers must end with specific offsets` en die nuwe **Deviation**-skuifbalk (≥7.4) verminder vals positiewe resultate aansienlik wanneer jy ná 'n update herskandeer. Gebruik dit saam met multi-map-vergelyking (`.PTR` → *Compare results with other saved pointer map*) om binne slegs 'n paar minute 'n **enkele veerkragtige basis-pointer** te verkry.
* Kortpad vir grootmaatfiltrering: druk ná die eerste scan `Ctrl+A → Space` om alles te merk, en daarna `Ctrl+I` (invert) om adresse wat die herscan nie geslaag het nie, te ontkies.

### Ultimap 3 – Intel PT tracing
*Vanaf 7.5 is die ou Ultimap herimplementeer bo-op **Intel Processor-Trace (IPT)**.* Dit beteken dat jy nou **elke branch wat die teiken neem, kan opneem** sonder om stapsgewys uit te voer (slegs user-mode; dit sal die meeste anti-debug-gadgets nie aktiveer nie).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Na ’n paar sekondes stop die capture en **regskliek → Save execution list to file**. Kombineer branch addresses met ’n `Find out what addresses this instruction accesses`-sessie om hoëfrekwensie game-logic-hotspots uiters vinnig op te spoor.

### 1-byte `jmp` / auto-patch templates
Weergawe 7.5 het ’n *one-byte* JMP-stub (0xEB) bekendgestel wat ’n SEH-handler installeer en ’n INT3 by die oorspronklike ligging plaas. Dit word outomaties gegenereer wanneer jy **Auto Assembler → Template → Code Injection** gebruik op instruksies wat nie met ’n 5-byte relative jump gepatch kan word nie. Dit maak “tight” hooks binne packed of size-constrained routines moontlik.<sup>[[1]](#references)</sup>

### Kernel-level stealth met DBVM (AMD & Intel)
*DBVM* is CE se ingeboude Type-2-hypervisor. Onlangse builds het uiteindelik **AMD-V/SVM support** bygevoeg, sodat jy `Driver → Load DBVM` op Ryzen/EPYC-hosts kan uitvoer. DBVM stel jou in staat om:
1. Hardware breakpoints te skep wat onsigbaar is vir Ring-3/anti-debug checks.
2. Pageable of protected kernel memory-regions te lees/skryf, selfs wanneer die user-mode driver gedeaktiveer is.
3. VM-EXIT-less timing-attack bypasses uit te voer (byvoorbeeld om `rdtsc` vanaf die hypervisor te query).

**Wenk:** DBVM sal weier om te laai wanneer HVCI/Memory-Integrity op Windows 11 geaktiveer is → skakel dit af of boot ’n toegewyde VM-host.

### Remote / cross-platform debugging met **ceserver**
CE word nou saam met ’n volledige rewrite van *ceserver* gelewer en kan oor TCP aan **Linux, Android, macOS & iOS**-targets attach. ’n Gewilde fork integreer *Frida* om dynamic instrumentation met CE se GUI te kombineer – ideaal wanneer jy Unity- of Unreal-games wat op ’n foon loop, moet patch:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Vir die Frida bridge, sien `bb33bb/frida-ceserver` op GitHub.<sup>[[1]](#references)[[2]](#references)</sup>

### Ander noemenswaardige funksies
* **Patch Scanner** (MemView → Tools) – bespeur onverwagte kodeveranderings in uitvoerbare afdelings; nuttig vir malware-analise.
* **Structure Dissector 2** – sleep 'n adres → `Ctrl+D`, en kies dan *Guess fields* om C-structures outomaties te evalueer.
* **.NET & Mono Dissector** – verbeterde Unity-gameondersteuning; roep metodes direk vanuit die CE Lua-console aan.
* **Big-Endian custom types** – skandeer/redigeer met omgekeerde byte-volgorde (nuttig vir console-emulators en netwerkpakketbuffers).
* **Autosave & tabs** vir AutoAssembler/Lua-vensters, plus `reassemble()` vir die herskryf van instruksies oor verskeie lyne.<sup>[[1]](#references)</sup>

### Installation & OPSEC-aantekeninge (2024-2025)
* Die amptelike installer is toegedraai met InnoSetup **ad-offers** (`RAV` ens.). **Klik altyd *Decline*** *of compile from source* om PUPs te vermy. AVs sal steeds `cheatengine.exe` as 'n *HackTool* vlag, wat verwag word.
* Moderne anti-cheat drivers (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) bespeur CE se window class selfs wanneer dit hernoem is. Gebruik jou reversing-kopie **binne 'n weggooibare VM** of nadat network play gedeaktiveer is.
* Indien jy slegs user-mode access benodig, kies **`Settings → Extra → Kernel mode debug = off`** om te voorkom dat CE se unsigned driver gelaai word, wat 'n BSOD op Windows 11 24H2 Secure-Boot kan veroorsaak.

---

## Verwysings

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)

{{#include ../../banners/hacktricks-training.md}}
