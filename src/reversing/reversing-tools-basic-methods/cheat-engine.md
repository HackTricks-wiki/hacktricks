# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes binne die memory van 'n lopende game gestoor word en dit te verander.\
Wanneer jy dit aflaai en uitvoer, word jy 'n **tutorial** aangebied oor hoe om die tool te gebruik. As jy wil leer hoe om die tool te gebruik, word dit sterk aanbeveel dat jy dit voltooi.

## Waarna soek jy?

![Cheat Engine - Waarna soek jy?: Waarna soek jy?](<../../images/image (762).png>)

Hierdie tool is baie nuttig om te vind **waar een of ander waarde** (gewoonlik 'n getal) **in die memory** van 'n program **gestoor word**.\
**Getalle** word **gewoonlik** in **4bytes**-formaat gestoor, maar jy kan dit ook in **double**- of **float**-formate vind, of jy wil dalk na iets **anders as 'n getal** soek. Daarom moet jy seker maak jy **selekteer** waarna jy wil **soek**:

![Cheat Engine - Waarna soek jy?: Getalle word gewoonlik in 4bytes-formaat gestoor, maar jy kan dit ook in double- of float-formate vind, of jy wil dalk na iets...](<../../images/image (324).png>)

Jy kan ook **verskillende** tipes **searches** aandui:

![Cheat Engine - Waarna soek jy?: Jy kan ook verskillende tipes searches aandui](<../../images/image (311).png>)

Jy kan ook die blokkie merk om die **game te stop terwyl die memory geskandeer word**:

![Cheat Engine - Waarna soek jy?: Jy kan ook die blokkie merk om die game te stop terwyl die memory geskandeer word](<../../images/image (1052).png>)

### Hotkeys

In _**Edit --> Settings --> Hotkeys**_ kan jy verskillende **hotkeys** vir verskillende doeleindes instel, soos om die **game te stop** (wat nogal nuttig is as jy op 'n stadium die memory wil scan). Ander opsies is beskikbaar:

![Waarna soek jy? - Hotkeys: In Edit -- Settings -- Hotkeys kan jy verskillende hotkeys vir verskillende doeleindes instel, soos om die game te stop (wat nogal nuttig is as jy op 'n stadium...](<../../images/image (864).png>)

## Wysiging van die waarde

Sodra jy **gevind** het waar die **waarde** waarna jy **soek** is (meer hieroor in die volgende stappe), kan jy dit **wysig** deur dit te dubbelklik en dan sy waarde te dubbelklik:

![Hotkeys - Wysiging van die waarde: Sodra jy gevind het waar die waarde waarna jy soek is (meer hieroor in die volgende stappe), kan jy dit wysig deur dit te dubbelklik en dan te dubbelklik...](<../../images/image (563).png>)

En uiteindelik deur die **merkblokkie te merk** sodat die wysiging in die memory uitgevoer word:

![Hotkeys - Wysiging van die waarde: En uiteindelik deur die merkblokkie te merk sodat die wysiging in die memory uitgevoer word](<../../images/image (385).png>)

Die **verandering** aan die **memory** sal onmiddellik **toegepas** word (let daarop dat die waarde **nie in die game opgedateer sal word nie** totdat die game hierdie waarde weer gebruik).

## Soek na die waarde

Kom ons aanvaar dus dat daar 'n belangrike waarde is (soos die lewe van jou user) wat jy wil verbeter, en dat jy hierdie waarde in die memory soek)

### Deur 'n bekende verandering

As jy aanvaar dat jy die waarde 100 soek, **voer jy 'n scan uit** wat na daardie waarde soek, en jy vind baie treffers:

![Soek na die waarde - Deur 'n bekende verandering: As jy aanvaar dat jy die waarde 100 soek, voer jy 'n scan uit wat na daardie waarde soek, en jy vind baie treffers](<../../images/image (108).png>)

Dan doen jy iets sodat die **waarde verander**, en jy **stop** die game en **voer 'n** **next scan** uit:

![Soek na die waarde - Deur 'n bekende verandering: Dan doen jy iets sodat die waarde verander, en jy stop die game en voer 'n next scan uit](<../../images/image (684).png>)

Cheat Engine sal soek na die **waardes** wat **van 100 na die nuwe waarde verander het**. Baie geluk, jy het die **adres** van die waarde waarna jy gesoek het **gevind**, en jy kan dit nou wysig.\
_As jy steeds verskeie waardes het, doen iets om daardie waarde weer te wysig, en voer nog 'n "next scan" uit om die adresse te filtreer._

### Onbekende waarde, bekende verandering

In die scenario waar jy **nie die waarde ken nie**, maar jy weet **hoe om dit te laat verander** (en selfs wat die waarde van die verandering is), kan jy na jou getal soek.

Begin dus deur 'n scan van die tipe "**Unknown initial value**" uit te voer:

![Deur 'n bekende verandering - Onbekende waarde, bekende verandering: Begin dus deur 'n scan van die tipe " Unknown initial value " uit te voer](<../../images/image (890).png>)

Laat die waarde dan verander, dui aan **hoe** die **waarde** **verander het** (in my geval is dit met 1 verminder), en voer 'n **next scan** uit:

![Deur 'n bekende verandering - Onbekende waarde, bekende verandering: Laat die waarde dan verander, dui aan hoe die waarde verander het (in my geval is dit met 1 verminder), en voer 'n next scan uit](<../../images/image (371).png>)

Jy sal **al die waardes sien wat op die geselekteerde manier gewysig is**:

![Deur 'n bekende verandering - Onbekende waarde, bekende verandering: Jy sal al die waardes sien wat op die geselekteerde manier gewysig is](<../../images/image (569).png>)

Sodra jy jou waarde gevind het, kan jy dit wysig.

Let daarop dat daar **baie moontlike veranderinge** is en dat jy hierdie **stappe soveel keer as wat jy wil** kan uitvoer om die resultate te filtreer:

![Deur 'n bekende verandering - Onbekende waarde, bekende verandering: Let daarop dat daar baie moontlike veranderinge is en dat jy hierdie stappe soveel keer as wat jy wil kan uitvoer om die resultate te filtreer](<../../images/image (574).png>)

### Ewekansige Memory Address - Vind die kode

Tot dusver het ons geleer hoe om 'n adres te vind wat 'n waarde stoor, maar dit is hoogs waarskynlik dat daardie adres **in verskillende uitvoerings van die game op verskillende plekke in die memory** sal wees. Kom ons vind dus uit hoe om daardie adres altyd te vind.

Gebruik sommige van die genoemde truuks om die adres te vind waar jou huidige game die belangrike waarde stoor. Doen dan (stop die game as jy wil) 'n **regsklik** op die gevonde **adres** en selekteer "**Find out what accesses this address**" of "**Find out what writes to this address**":

![Onbekende waarde, bekende verandering - Ewekansige Memory Address - Vind die kode: Gebruik sommige van die genoemde truuks om die adres te vind waar jou huidige game die belangrike waarde stoor. Doen dan...](<../../images/image (1067).png>)

Die **eerste opsie** is nuttig om te weet watter **dele** van die **kode** hierdie **adres gebruik** (wat nuttig is vir meer dinge, soos om te weet **waar jy die game se kode kan wysig**).\
Die **tweede opsie** is meer **spesifiek**, en sal in hierdie geval nuttiger wees, aangesien ons wil weet **waarvandaan hierdie waarde geskryf word**.

Sodra jy een van hierdie opsies geselekteer het, sal die **debugger** aan die program **gekoppel** word en 'n nuwe **leë venster** sal verskyn. **Speel** nou die **game** en **wysig** daardie **waarde** (sonder om die game te herbegin). Die **venster** behoort gevul te word met die **adresse** wat die **waarde wysig**:

![Onbekende waarde, bekende verandering - Ewekansige Memory Address - Vind die kode: Sodra jy een van hierdie opsies geselekteer het, sal die debugger aan die program gekoppel word en 'n nuwe leë venster...](<../../images/image (91).png>)

Noudat jy die adres gevind het wat die waarde wysig, kan jy die **kode na jou smaak wysig** (Cheat Engine laat jou toe om dit baie vinnig na NOPs te wysig):

![Onbekende waarde, bekende verandering - Ewekansige Memory Address - Vind die kode: Noudat jy die adres gevind het wat die waarde wysig, kan jy die kode na jou smaak wysig (Cheat Engine...](<../../images/image (1057).png>)

Jy kan dit dus nou wysig sodat die kode nie jou getal beïnvloed nie, of dit altyd op 'n positiewe manier beïnvloed.

### Ewekansige Memory Address - Vind die pointer

Volg die vorige stappe en vind waar die waarde waarin jy belangstel is. Gebruik dan "**Find out what writes to this address**" om uit te vind watter adres hierdie waarde skryf, en dubbelklik daarop om die disassembly-aansig te kry:

![Ewekansige Memory Address - Vind die kode - Ewekansige Memory Address - Vind die pointer: Volg die vorige stappe en vind waar die waarde waarin jy belangstel is. Gebruik dan " Find out...](<../../images/image (1039).png>)

Voer dan 'n nuwe scan uit wat **na die hex-waarde tussen "\[]"** soek (die waarde van $edx in hierdie geval):

![Ewekansige Memory Address - Vind die kode - Ewekansige Memory Address - Vind die pointer: Voer dan 'n nuwe scan uit wat na die hex-waarde tussen " ()" soek (die waarde van $edx in hierdie geval)](<../../images/image (994).png>)

(_As verskeie verskyn, het jy gewoonlik die een met die kleinste adres nodig_)\
Ons het nou die **pointer gevind wat die waarde waarin ons belangstel sal wysig**.

Klik op "**Add Address Manually**":

![Ewekansige Memory Address - Vind die kode - Ewekansige Memory Address - Vind die pointer: Klik op " Add Address Manually "](<../../images/image (990).png>)

Klik nou op die "Pointer"-merkblokkie en voeg die gevonde adres in die teksblokkie by (in hierdie scenario was die gevonde adres in die vorige prent "Tutorial-i386.exe"+2426B0):

![Ewekansige Memory Address - Vind die kode - Ewekansige Memory Address - Vind die pointer: Klik nou op die "Pointer"-merkblokkie en voeg die gevonde adres in die teksblokkie by (in hierdie scenario,...](<../../images/image (392).png>)

(Let op hoe die eerste "Address" outomaties ingevul word met die pointer-adres wat jy ingevoer het)

Klik OK en 'n nuwe pointer sal geskep word:

![Ewekansige Memory Address - Vind die kode - Ewekansige Memory Address - Vind die pointer: Klik OK en 'n nuwe pointer sal geskep word](<../../images/image (308).png>)

Nou, elke keer wanneer jy daardie waarde wysig, **wysig jy die belangrike waarde, selfs al verskil die memory-adres waar die waarde is.**

### Code Injection

Code injection is 'n tegniek waar jy 'n stuk kode in die teikenproses inject, en dan die uitvoering van kode herlei om deur jou eie geskrewe kode te gaan (soos om vir jou punte te gee in plaas daarvan om dit weg te neem).

Stel jou voor jy het die adres gevind wat 1 van jou speler se lewe aftrek:

![Ewekansige Memory Address - Vind die pointer - Code Injection: Stel jou voor jy het die adres gevind wat 1 van jou speler se lewe aftrek](<../../images/image (203).png>)

Klik op Show disassembler om die **disassembled code** te kry.\
Klik dan **CTRL+a** om die Auto assemble-venster oop te maak en selekteer _**Template --> Code Injection**_

![Ewekansige Memory Address - Vind die pointer - Code Injection: Klik dan CTRL+a om die Auto assemble-venster oop te maak en selekteer Template -- Code Injection](<../../images/image (902).png>)

Vul die **adres van die instruksie wat jy wil wysig** in (dit word gewoonlik outomaties ingevul):

![Ewekansige Memory Address - Vind die pointer - Code Injection: Vul die adres van die instruksie wat jy wil wysig in (dit word gewoonlik outomaties ingevul)](<../../images/image (744).png>)

'n Template sal gegenereer word:

![Ewekansige Memory Address - Vind die pointer - Code Injection: 'n Template sal gegenereer word](<../../images/image (944).png>)

Voeg dus jou nuwe assembly-kode in die "**newmem**"-afdeling in en verwyder die oorspronklike kode uit "**originalcode**" as jy nie wil hê dit moet uitgevoer word nie**.** In hierdie voorbeeld sal die injected code 2 punte byvoeg in plaas daarvan om 1 af te trek:

![Ewekansige Memory Address - Vind die pointer - Code Injection: Voeg dus jou nuwe assembly-kode in die " newmem "-afdeling in en verwyder die oorspronklike kode uit die " originalcode " as jy...](<../../images/image (521).png>)

**Klik op execute ensovoorts, en jou kode behoort in die program geïnject te word, wat die gedrag van die funksionaliteit verander!**

## Relocation-safe code injection with AOB signatures

'n Script wat `game.exe+123456` hook, kan ná ASLR of 'n software update breek. 'n **Array of Bytes (AOB) signature** vind die instruksie uit sy omliggende machine code. Gebruik `aobscanmodule` om die search tot een module te beperk. Maak die signature lank genoeg om een match terug te gee. Gebruik wildcards vir relocation-bytes, adresse en ander bytes wat kan verander. Moenie die hele instruksie wat jy moet herstel met wildcards aandui nie.<sup>[[4]](#references)</sup>

In Memory View, selekteer die instruksie en gebruik **Tools → Auto Assemble → Template → AOB Injection**. Die gegenereerde `[DISABLE]`-blok is belangrik. Dit moet elke oorskryfde byte herstel en die allocation vrystel.<sup>[[4]](#references)</sup>

<details>
<summary>Minimale x64 AOB injection-skelet</summary>
```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
movss [rbx+000000A0],xmm0
jmp return
INJECT:
jmp newmem
nop
nop
nop
return:
[DISABLE]
INJECT:
db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```
</details>

Voordat jy die script aktiveer, verifieer hierdie punte:

1. Die AOB gee **een** adres terug. Voeg stabiele instruksies aan albei kante by as dit meer as een teruggee.
2. Die jump vervang volledige instruksies. Moet nooit ’n instruksie verdeel nie.
3. Die toegewese cave is bereikbaar deur die gegenereerde jump. Op x64 kan ’n verafgeleë toewysing ’n 14-grepe jump benodig.
4. Die injected code behou registers, flags en stack alignment wat die oorspronklike funksie verwag.
5. Die disable-blok herstel die presiese oorspronklike bytes. Toets enable en disable verskeie kere voordat jy die tabel stoor.

## Betroubare pointer-werkvloei

’n Pointer wat in een uitvoering gevind word, is slegs ’n kandidaat. Bou pointer maps in verskeie vars uitvoerings en scan weer teen almal. Herbegin die target tussen captures sodat ASLR en heap-toewysings verander. Verkies paths waarvan die basis ’n module of ’n ander stabiele simbool is. Verwerp paths wat slegs met een save, level of object instance werk.

Die **pointer must end with specific offsets**-filter en sy deviation-opsie kan bruikbare paths behou wanneer ’n nabygeleë field tussen builds verskuif. Die 7.5 release het ook hierdie deviation-beheer bygevoeg. Dit is ’n filter, nie bewys dat ’n pointer chain stabiel is nie.<sup>[[1]](#references)</sup>

Wanneer ’n structure te gereeld verskuif vir pointer scanning, hook die instruksie wat daartoe toegang verkry. Capture die live object pointer vanaf ’n register na ’n toegewese simbool. Dit is dikwels meer betroubaar vir entity lists en managed objects.

## Nasporing van code in plaas van scanning van waardes

Gebruik **Find out what writes to this address** wanneer die waarde direk gewysig word. Gebruik **Find out what accesses this address** wanneer jy die owning object benodig of wanneer die write deur copied data plaasvind. Trigger slegs een aksie in die target. Vergelyk dan die hit count en register state.

**Ultimap 2** gebruik Intel Processor Trace op ondersteunde Intel CPUs. Dit teken uitgevoerde control flow aan met minder onderbreking as om elke instruksie te step. Filter vir code wat uitgevoer is terwyl die interessante aksie plaasgevind het en verwyder code wat ook tydens ’n idle capture uitgevoer is. Intel PT is nie ’n stealth feature nie. Die target kan steeds tracing, timing changes of Cheat Engine self detecteer.<sup>[[1]](#references)</sup>

Cheat Engine 7.5 het ook ’n Intel PT-interface bygevoeg wat deur Windows verskaf word. Die ouer DBVM-backed Ultimap mode en die Intel PT-mode het verskillende hardware- en OS-vereistes. Moenie aanvaar dat ’n DBVM-capable CPU Intel PT ondersteun nie.<sup>[[1]](#references)</sup>

## Debugger- en breakpoint-keuse

Kies die debugger wat die minste inmeng en wat werk:

- **Windows debugger** is eenvoudig, maar skep normale debug events. Anti-debugging checks kan dit detecteer.
- **VEH debugger** hanteer breakpoints deur ’n vectored exception handler. Dit vermy sommige basiese debugger checks, maar dit is nie onsigbaar nie.
- **Hardware breakpoints** patch nie die instruction bytes nie, maar x86/x64 bied slegs ’n klein aantal debug-register slots.
- **Software breakpoints** vervang ’n byte met `INT3`. Hulle is maklik om te detecteer en kan met integrity checks bots.
- **DBVM debugger** verskuif sommige bewerkings onder die guest OS. Dit het baie meer privilege en kan die host laat crash as dit verkeerd gekonfigureer is.

Cheat Engine 7.5 kan ’n one-byte jump gebruik wat op ’n exception handler en `INT3` gebaseer is wanneer daar nie genoeg ruimte vir ’n normale relative jump is nie. Behandel dit soos ’n software breakpoint. Verifieer exception flow en moenie aanvaar dat dit anti-tamper checks omseil nie.<sup>[[1]](#references)</sup>

DBVM is ’n hypervisor, nie ’n algemene invisibility switch nie. Gebruik dit slegs in ’n disposable lab. Moenie sy control interface aan untrusted code blootstel nie. Kernel anti-cheat- en endpoint-produkte kan steeds die driver, hypervisor state of modified memory detecteer.

## Managed runtimes en onlangse 7.6/7.7-features

Vir Mono-, IL2CPP-, .NET- en Java-targets, verkies runtime metadata bo blind scans wanneer dit beskikbaar is. Maak **Mono → Activate mono features** of die ooreenstemmende runtime information window oop. Vind eers die class, field of method. Gebruik dan die native disassembly wanneer die managed method JIT-compiled is.

Die 7.6-lyn het `AOBSCANEX` vir executable-memory-only signatures, ’n `gdbserver` debugger interface, Java metadata inspection, vinniger IL2CPP-enumeration en ’n pointer-scan-opsie bygevoeg wat die boonste pointer byte ignoreer wat deur ARM memory tagging gebruik word. Die 7.7-lyn het native Linux builds, `HOOK`/`UNHOOK`, `aobscanfunction`, beter generic Mono method lookup, verbeterde PDB structure support en basiese Unreal Engine structure dissection bygevoeg.<sup>[[3]](#references)</sup>

Hierdie toevoegings maak ’n nuttige werkvloei moontlik:

1. Resolve ’n managed method of static field vanuit metadata.
2. Trace of disassembleer die native code wat vir daardie method geproduseer word.
3. Gebruik `AOBSCANEX` of `aobscanfunction` om ’n stabiele executable signature te vind.
4. Generate ’n reversible hook. Behou die oorspronklike instruksies en valideer die disable path.
5. Kontroleer die signature weer ná elke target update. ’n Suksesvolle match waarborg nie dat die omliggende logic steeds dieselfde betekenis het nie.

## Remote targets met `ceserver`

`ceserver` stel process enumeration, memory access en debugging aan die Cheat Engine GUI bloot. Amptelike builds dek Linux en Android. Run die ooreenstemmende architecture op die target en connect deur die **Network**-tab. Op Android voorkom forwarding van die default port dat dit op die network blootgestel word:<sup>[[3]](#references)</sup>
```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```
Die derdeparty-`frida-ceserver`-bridge kan ’n Cheat Engine-versoenbare koppelvlak vir iOS-teikens verskaf. Dit is nie die amptelike `ceserver` nie, en die ondersteunde bewerkings kan verskil.<sup>[[2]](#references)</sup>

Aanvaar dat die protokol debugger-vlaktoegang verleen. Bind dit aan loopback of plaas dit agter ’n SSH/ADB-tunnel. Moet TCP 52736 nooit aan ’n onbetroubare netwerk blootstel nie. Stop die server wanneer die sessie eindig.

## Operasionele veiligheid

Heg slegs aan sagteware wat jy besit of gemagtig is om te toets. Moenie Cheat Engine langs ’n aanlyn speletjie of production endpoint uitvoer nie. Geheueskrywings, injected code, drivers en DBVM kan die teiken laat crash of korrupteer.<sup>[[3]](#references)</sup>

Laai builds van die amptelike webwerf af of compile die gepubliseerde source. Security products klassifiseer dikwels memory editors, debuggers en hul drivers as hack tools. Moenie host protection globaal deaktiveer nie. Gebruik ’n toegewyde VM of lab-host en verifieer die artifact voordat jy dit uitvoer.<sup>[[3]](#references)</sup>



## References

- [1] [Cheat Engine 7.5-vrystellingsnotas](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver bridge for remote targets](https://github.com/gmh5225/frida-ceserver)
- [3] [Cheat Engine amptelike vrystellingsnuus](https://www.cheatengine.org/)
- [4] [Cheat Engine Wiki: Auto Assembler AOBs](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
