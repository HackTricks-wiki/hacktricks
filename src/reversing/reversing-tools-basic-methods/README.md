# Omgekeerde ingenieurswese-gereedskap en basiese metodes

{{#include ../../banners/hacktricks-training.md}}

## ImGui-gebaseerde gereedskap vir omgekeerde ingenieurswese

Sagteware:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg-outomatisering in gebruikersmodus

{{#ref}}
windbg-automation.md
{{#endref}}

## Makro-analise van Office-dokumente

Vir verdagte Office-dokumente, ondersoek [VBA macro junk code and hidden UserForm controls](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

## Beheervloei deur Windows-uitsonderings

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Windows-kernelfoutopsporing

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm-dekompileerder / Wat-samesteller

Aanlyn:

- Gebruik [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) om van wasm (binêr) na wat (gewone teks) te **dekompileer**
- Gebruik [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) om van wat na wasm te **saamstel**
- Jy kan ook [web-wasmdec](https://wwwg.github.io/web-wasmdec/) vir dekompilering probeer.

Sagteware:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8-gekasheerde bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Gevirtualiseerde payloads en pasgemaakte VM's

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET-dekompileerder

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is 'n dekompileerder wat **verskeie formate dekompileer en ondersoek**, insluitend **biblioteke** (.dll), **Windows-metadata-lêers** (.winmd) en **uitvoerbare lêers** (.exe). Nadat 'n assembly gedekompileer is, kan dit as 'n Visual Studio-projek (.csproj) gestoor word.

Die voordeel hiervan is dat hierdie proses tyd kan bespaar as verlore bronkode uit 'n verouderde assembly herstel moet word. dotPeek bied ook gerieflike navigasie deur die gedekompileerde kode, wat dit een van die ideale gereedskap vir **Xamarin-algoritme-analise** maak.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Met 'n omvattende byvoegingsmodel en 'n API wat die gereedskap uitbrei om aan jou presiese behoeftes te voldoen, bespaar .NET Reflector tyd en vereenvoudig dit ontwikkeling. Kom ons kyk na die talle dienste vir omgekeerde ingenieurswese wat hierdie gereedskap bied:

- Gee insig in hoe data deur 'n biblioteek of komponent vloei
- Gee insig in die implementering en gebruik van .NET-tale en -raamwerke
- Vind ongedokumenteerde en nie-blootgestelde funksionaliteit om meer uit die gebruikte API's en tegnologieë te haal.
- Vind afhanklikhede en verskillende assemblies
- Vind die presiese ligging van foute in jou kode, derdeparty-komponente en biblioteke.
- Foutspoor die bronkode van al die .NET-kode waarmee jy werk.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Jy kan dit op enige bedryfstelsel gebruik (jy kan dit direk vanaf VSCode installeer; jy hoef nie die git af te laai nie. Klik op **Extensions** en **search ILSpy**).\
As jy weer wil **dekompileer**, **wysig** en **herkompileer**, kan jy [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) of 'n aktief onderhoude fork daarvan, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), gebruik. (**Right Click -> Modify Method** om iets binne 'n funksie te verander).

### Bestuurde inspeksie met REA sonder uitvoering

**REA** kan PE/CLI-metadata en CIL inspekteer sonder om die assembly te laai. Begin met die artefak se identiteit en inspekteer dan lede en verklaarde inheemse grense; dit is nuttig wanneer verdagte oproepe nagegaan word voordat 'n dekompileerder gebruik of die program uitgevoer word.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Vir weergawevergelyking gebruik `compare_managed_members` rou CIL-/handtekening-identiteit en vingerafdrukke van gedekodeerde instruksies, eerder as om metadata-tokens as stabiel tussen bouwe te beskou. ’n P/Invoke-verklaring bewys nie dat native kode uitgevoer is nie; `verify_managed_native_boundaries` benodig ’n ooreenstemmende native uitvoer of funksiebewys om daardie grens te kontroleer. Bewaar die artefakdigest, MVID en onopgeloste karterings saam met die resultaat.<sup>[[17]](#references)</sup>

### DNSpy-logging

Om **DNSpy sekere inligting in ’n lêer te laat aanteken**, kan jy hierdie kodebrokkie gebruik:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy-ontfouting

Om kode met DNSpy te ontfout, moet jy:

Verander eers die **Assembly-attribuutwaardes** wat met **ontfouting** verband hou:

![DNSpy Logging - DNSpy-ontfouting: Verander eers die Assembly-attribuutwaardes wat met ontfouting verband hou](<../../images/image (973).png>)

Van:

```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```

Aan:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```

En klik op **compile**:

![DNSpy Logging - DNSpy Debugging: En klik op compile](<../../images/image (314) (1).png>)

Stoor dan die nuwe lêer via _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Stoor dan die nuwe lêer via File Save module](<../../images/image (602).png>)

Dit is nodig, want as jy dit nie doen nie, sal verskeie **optimaliserings** tydens **runtime** op die kode toegepas word, en dit kan gebeur dat ’n **breakpoint nooit getref word** terwyl jy debugging doen, of dat sommige **veranderlikes nie bestaan nie**.

As jou .NET-toepassing dan deur **IIS** uitgevoer word, kan jy dit **herbegin** met:

```
iisreset /noforce
```

Om nou te begin ontfout, moet jy al die oop lêers sluit en **Attach to Process...** in die **Debug Tab** kies:

![DNSpy Logging - DNSpy Debugging: Om nou te begin ontfout, moet jy al die oop lêers sluit en Attach to Process in die Debug Tab kies](<../../images/image (318).png>)

Kies dan **w3wp.exe** om aan die **IIS server** te koppel en klik **attach**:

![DNSpy Logging - DNSpy Debugging: Kies dan w3wp.exe om aan die IIS server te koppel en klik attach](<../../images/image (113).png>)

Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers **Debug >> Break All** en klik dan **_Debug >> Windows >> Modules_**:

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers Debug Break All en klik dan Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers Debug Break All en klik dan Debug Windows Modules](<../../images/image (834).png>)

Klik op enige module in **Modules** en kies **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Klik op enige module in Modules en kies Open All Modules](<../../images/image (922).png>)

Regsklik op enige module in **Assembly Explorer** en klik **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Regsklik op enige module in Assembly Explorer en klik Sort Assemblies](<../../images/image (339).png>)

## Java-dekompileerder

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL-ontfouting

### Met IDA

- **Laai rundll32** (64-bis in C:\Windows\System32\rundll32.exe en 32-bis in C:\Windows\SysWOW64\rundll32.exe)
- Kies die **Windbg**-ontfouter
- Kies "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Kies " Suspend on library load/unload "](<../../images/image (868).png>)

- Stel die **parameters** vir die uitvoering op deur die **pad na die DLL** en die funksie wat jy wil aanroep, in te vul:

![Debugging DLLs - Using IDA: Stel die parameters vir die uitvoering op deur die pad na die DLL en die funksie wat jy wil aanroep, in te vul](<../../images/image (704).png>)

Wanneer jy dan begin ontfout, **sal die uitvoering stop wanneer elke DLL gelaai word**. Die uitvoering sal dus stop wanneer rundll32 jou DLL laai.

Hierdie metode stop by module-laaigebeurtenisse, maar dit is minder regstreeks as met die x64dbg-werkvloei hieronder om die gelaaide DLL se toegangspunt te bereik.

### Met x64dbg/x32dbg

- **Laai rundll32** (64-bis in C:\Windows\System32\rundll32.exe en 32-bis in C:\Windows\SysWOW64\rundll32.exe)
- **Verander die Command Line** (_File --> Change Command Line_) en stel die pad na die DLL en die funksie wat jy wil aanroep in, byvoorbeeld: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Verander _Options --> Settings_ en kies "**DLL Entry**".
- **Begin dan die uitvoering**. Die ontfouter sal by elke DLL se main stop; op ’n sekere punt sal jy **by jou DLL se Entry stop**. Soek van daar af na die punte waar jy ’n breakpoint wil plaas.

Let daarop dat wanneer die uitvoering om enige rede in win64dbg stop, jy kan sien **in watter kode jy is** deur boaan die win64dbg-venster te kyk:

![Using IDA - Using x64dbg/x32dbg: Let daarop dat wanneer die uitvoering om enige rede in win64dbg stop, jy kan sien in watter kode jy is deur boaan die win64dbg-venster te kyk](<../../images/image (842).png>)

Hierdie aanwyser bevestig wanneer die uitvoering binne die DLL wat jy wil ontfout, gestop het.

## GUI-toepassings / videospeletjies

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is ’n nuttige program om te vind waar belangrike waardes in die geheue van ’n lopende speletjie gestoor word en om dit te verander. Meer inligting by:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is ’n front-end-/reverse-engineering-nutsding vir die GNU Project Debugger (GDB), met die fokus op speletjies. Dit kan egter vir enige reverse-engineering-verwante werk gebruik word.

[**Decompiler Explorer**](https://dogbolt.org/) is ’n web-front-end vir ’n aantal dekompileerders. Met hierdie webdiens kan jy die uitvoer van verskillende dekompileerders op klein uitvoerbare lêers vergelyk.

### Godot PCK-dekripsie en projekherstel

Vir ’n verspreide Godot-speletjie, soek die PCK in ’n selfstandige `.pck`, ’n aangehegte of ingebedde uitvoerbare pakket, of ’n APK se `assets`-gids. [gore](https://github.com/figurophobia/gore) kan die pakket inspekteer en uittrek, terwyl volledige rekonstruksie van skrifte en hulpbronne GDRE Tools vereis (`gore setup` installeer dit, of gebruik `--gdre`). Die nutsding ondersteun Godot 4.x PCK-formate v2–v4 vir hierdie werkvloei; dit kan v1-opskrifte opspoor, maar vereis ’n verskafte sleutel vir v1.<sup>[[25]](#references)</sup>

Outomatiese sleutelherwinning vereis ’n geënkripteerde lêertabel; as slegs die lêerinhoud geënkripteer is, verskaf eerder ’n bekende sleutel. ’n Mislukte herstel bewys nie dat ’n pakket ongeënkripteer is nie.<sup>[[28]](#references)</sup>

Die sleutelsoektog is **nie** ’n AES-256-sleutelruimte-aanval nie. ’n Geënkripteerde lêertabel stel die MD5 van die ongeënkripteerde teks, die lengte van die ongeënkripteerde teks, die IV en die AES-256-CFB-syferteks bloot.<sup>[[27]](#references)</sup> `gore` toets 32-grepe-vensters van die speletjie se uitvoerbare lêer of nabygeleë lêers as kandidaatsleutels. Dit filter kandidate volgens aanneemlike gedekripteerde padlengte en -voorvoegsel, en bevestig dan treffers van die binêre skandering deur die hele tabel te dekripteer en sy MD5 na te gaan.<sup>[[26]](#references)[[28]](#references)</sup> Dit soek eers geïnisialiseerde PE/ELF-dataseksies en gebruik daarna ’n skandering van die hele lêer; `--scan` voeg ander kandidaat-lêers by.<sup>[[28]](#references)</sup>

As geen ingebedde sleutel gevind word nie, word ’n klein ingeboude wagwoordlys probeer; `--wordlist` verskaf ander kandidate. Elke wagwoord word getoets as die enjin se wagwoordafgeleide sleutelvoorstelling, ’n nul-opgevulde letterlike waarde of ’n sleutel van 64 heksadesimale karakters. Anders as treffers van die binêre skandering, slaag treffers uit die woordlys in hierdie implementering slegs die padstruktuurfilter. Bevestig dit deur die pakket oop te maak en die onttrekte hulpbronne te valideer.<sup>[[26]](#references)[[28]](#references)</sup>

Wanneer die speletjie-artefak plaaslik beskikbaar is, kies die stadium wat vir die ontleding nodig is. `recover` roep GDRE aan om ’n projek te rekonstrueer wat oopgemaak kan word, terwyl `extract` slegs die rou lêers uitpak. `key` druk ’n kandidaatsleutel uit om met ’n ander nutsding te gebruik.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Inheemse ondersoek met bewyse as grondslag deur REA

**REA** stel Hopper-, Ghidra- en IDA-analise via CLI en MCP beskikbaar. Dit vereis Node.js 22.x (ten minste 22.19), 24.x (ten minste 24.11) of 26+, plus npm. Stel eers ’n bestaande native provider op; kontroleer `rea providers --json` en kies ’n provider uitdruklik wanneer meer as een die teiken ondersteun. Gebruik hieronder ’n waargenome funksienaam of adres uit die inventaris in die plek van `0x1000`.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Begin met ’n feature-string of simbool, volg verwysings en callers, en inspekteer dan die geselekteerde funksiedossier en pseudokode met `rea decompile`. REA bind ’n sessie aan die geselekteerde provider, eerder as om dit stilweg ná ’n fout te vervang. Vir herhaalbare navrae hergebruik `--snapshot PATH` slegs ooreenstemmende artefakgrepe, provider, instellings, bewerking en parameters; ’n snapshot is ’n plaaslike kas, nie ’n gestoorde provider-databasis nie. Behou die teruggestuurde Evidence en eksplisiete onbekendes, eerder as om afgeleide paaie of decompiler-teks as oorspronklike bron te behandel.<sup>[[16]](#references)[[18]](#references)</sup>

Vir JavaScript/Electron-inskrywpunte wat na native add-ons lei, sien [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Geskripte IDA- en Ghidra-ontleding met ’n plaaslike TCP-brug

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) loop binne ’n **reeds oop** IDA-databasis of Ghidra CodeBrowser-program en laat ’n aparte script toe om daardie ontledingsdatabasis te navraag en te wysig. Voer `ID_Server.py` uit IDA se Python CLI uit (`import ID_Server`) of `Ghidra_Server.py` uit Ghidra se Script Manager. IDA bind aan `127.0.0.1` vanaf poort `5073` en skandeer hoër poorte. Die huidige Ghidra-script begin by poort `5093` en probeer tien poorte tot en met `5102`; sy Java-socket bind aan die wildcard-adres, nie net aan loopback nie. Gaan die poort na wat deur die instansie vertoon word voordat jy koppel. Anders as ’n headless analyzer werk hierdie brug op die program wat tans in daardie GUI-instansie oop is.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Stuur **een opdrag wat met ’n newline eindig per verbinding** en lees die antwoord wat met ’n newline eindig. Die resultaat is gewoonlik JSON. Byvoorbeeld, nadat jy ’n ingevoerde API gevind het wat met ’n invoerpad verband hou, vind `IMPORTXREF` die call sites; `DECOMP_XREF` decompileer dan die callers van ’n geselekteerde adres in bondels. `FUNC` inspekteer ’n funksie, terwyl `PCODE` die decompiler se intermediêre voorstelling teruggee. Gebruik die adres uit die aktiewe databasis, nie ’n adres wat van ’n binêre lêer met ’n ander rebase gekopieer is nie. Die voorbeeld hieronder gebruik IDA se verstekpoort; gebruik vir Ghidra die poort wat deur sy script vertoon word.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Dieselfde kanaal kan **die analisedatabasis verander**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` en `PATCH` verander name, tipes, struktuurdefinisies, funksiegrense of gestoorde grepe. `PATCH` is ’n databasiswysiging, **nie** bewys van ’n regstreekse prosespleister nie. Geen van die listeners dokumenteer verifikasie nie. IDA is slegs vir loopback beskikbaar, maar Ghidra kan dalk via netwerkkoppelvlakke bereik word; beperk toegang tot die Ghidra-listener wanneer jy dit gebruik. `QUIT` stop enigeen van die listeners, en IDA stel ook `ida_bridge_stop()` bloot.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Ontfouting van ’n shellcode met blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) allokeer die **shellcode**, druk sy **geheueadres** af en laat die uitvoering wag.\
Koppel ’n debugger soos IDA of x64dbg aan, stel ’n breakpoint by die afgedrukte adres en hervat die uitvoering om die shellcode te ontfout.

Die GitHub-releases-bladsy bevat zip-lêers met die saamgestelde releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Jy kan ’n effens gewysigde weergawe van Blobrunner by die volgende skakel vind. Om dit te compile, **skep net ’n C/C++-projek in Visual Studio Code, kopieer en plak die code en bou dit**.


{{#ref}}
blobrunner.md
{{#endref}}

### Ontfouting van ’n shellcode met jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) is soortgelyk aan BlobRunner. Dit allokeer die shellcode en betree ’n oneindige lus. Koppel die debugger aan, hervat vir **2–5 sekondes**, breek binne daardie lus en stap na die volgende oproep wat uitvoering na die geallokeerde shellcode oordra.

![Debugger gepouseer in jmp2it se oneindige lus, onmiddellik voor die oproep na die geallokeerde shellcode](<../../images/image (509).png>)

Jy kan ’n saamgestelde weergawe van [jmp2it op die releases-bladsy aflaai](https://github.com/adamkramer/jmp2it/releases/).

### Ontfouting van shellcode met Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is die GUI van radare. Met Cutter kan jy die shellcode emuleer en dit dinamies inspekteer.

Let daarop dat Cutter jou toelaat om "Open File" en "Open Shellcode" te kies. In my geval het dit die shellcode korrek gedecompileer toe ek dit as ’n lêer oopgemaak het, maar nie toe ek dit as shellcode oopgemaak het nie:

![Cutter wys verskillende ontledingsresultate wanneer dieselfde grepe as ’n lêer of as shellcode oopgemaak word](<../../images/image (562).png>)

Om die emulasie te begin op die plek wat jy wil, stel daar ’n bp; dit lyk of Cutter dan die emulasie outomaties daar begin:

![’n Breakpoint word by die gewenste shellcode-ingang gestel voordat Cutter-emulasie begin](<../../images/image (589).png>)

![Cutter-emulator gepouseer by die geselekteerde shellcode-breakpoint](<../../images/image (387).png>)

Jy kan byvoorbeeld die stack in ’n hex dump sien:

![Die geëmuleerde shellcode-stack word in Cutter se hex dump vertoon](<../../images/image (186).png>)

### Deobfuskeer van shellcode en verkryging van uitgevoerde funksies

Jy behoort [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) te probeer.\
Dit sal jou dinge vertel soos **watter funksies** die shellcode gebruik en of die shellcode homself in die geheue **dekodeer**.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg kom ook met ’n grafiese lanseerder waar jy die gewenste opsies kan kies en die shellcode kan uitvoer

![scDbg grafiese lanseerder om shellcode-emulasie- en nasporingsopsies te kies](<../../images/image (258).png>)

Die **Create Dump**-opsie sal die finale shellcode dump as enige veranderinge dinamies in die geheue aan die shellcode aangebring word (nuttig om die gedekodeerde shellcode af te laai). Die **start offset** kan nuttig wees om die shellcode by ’n spesifieke offset te begin. Die **Debug Shell**-opsie is nuttig om die shellcode met die scDbg-terminaal te ontfout (ek vind egter enige van die opsies wat vroeër verduidelik is beter hiervoor, aangesien jy Ida of x64dbg sal kan gebruik).

### Disassembleer met CyberChef

Laai jou shellcode-lêer as invoer op en gebruik die volgende resep om dit te disassembleer: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA-obfuscation-deobfuscation

**Mixed Boolean-Arithmetic (MBA)**-obfuscation verberg eenvoudige uitdrukkings soos `x + y` agter formules wat rekenkundige (`+`, `-`, `*`) en bitwyse operatore (`&`, `|`, `^`, `~`, verskuiwings) meng. Die belangrike punt is dat hierdie identiteite gewoonlik net korrek is onder **vaste-wydte-modulêre rekenkunde**, dus maak oordragte en oorlope saak:

```c
(x ^ y) + 2 * (x & y) == x + y
```

As jy hierdie soort uitdrukking met generiese algebra-instrumente vereenvoudig, kan jy maklik ’n verkeerde resultaat kry omdat die bitwydte-semantiek geïgnoreer is.<sup>[[1]](#references)</sup>

### Praktiese werkvloei

1. **Behou die oorspronklike bitwydte** van die geligte kode/IR/dekompileerder-uitvoer (`8/16/32/64` bits).
2. **Klassifiseer die uitdrukking** voordat jy dit probeer vereenvoudig:
   - **Lineêr**: geweegde somme van bitwise-atome
   - **Semilineêr**: lineêr plus konstante masks soos `x & 0xFF`
   - **Polinoom**: produkte kom voor
   - **Gemeng**: produkte en bitwise-logika is verweef, dikwels met herhaalde subuitdrukkings
3. **Verifieer elke kandidaat-herskrywing** met ewekansige toetsing of ’n SMT-bewys. As die ekwivalensie nie bewys kan word nie, behou die oorspronklike uitdrukking eerder as om te raai.

### Omseil afgeplatte beheer vloei met ’n smal uitvoeringsnitsel

Om die volledige beheer-vloeigrafiek te herwin, is dikwels onnodig. Met control-flow flattening, opaque predicates, groot dispatchers of MBA-swaar kode, volg verwysings vanaf geënkripteerde blobs en uitvoerbuffers na die kleinste roetine wat hulle transformeer. Reproduseer dan slegs daardie data-vloei-nitsel, of voer dit onafhanklik uit; die dispatcher is nie deel van die vereiste oplossing as die relevante toestand direk geïnisialiseer kan word nie.<sup>[[7]](#references)</sup>

’n Praktiese werkvloei is:<sup>[[7]](#references)</sup>

1. Inventariseer uitvoerbare en data-afdelings, relocations en kruisverwysings. Dump kandidaat-tabelle uit `.rodata` terwyl hul byte-volgorde en elementwydte behoue bly.
2. Identifiseer die laaste roetine wat die plaintext- of uitvoerbuffer skryf. Teken die invoere, verwysde tabelle, geïmporteerde oproepe en vereiste globale toestand aan.
3. Lig slegs daardie bewerkings na ’n Python-model met vaste wydte. As die nitsel steeds van te veel toestand afhang, roep die roetine onder Unicorn, QEMU of ’n debugger aan en hook irrelevante imports in plaas daarvan om die hele program te emuleer.
4. Valideer dat die extractor sy uitvoer werklik uit die verskafte binary aflei: verwyder stille fallbacks, soek daarin vir ingebedde antwoorde, en voer dit uit teen ongeïnspekteerde builds met veranderde strings, sleutels, identifiseerders, uitlegte en obfuscation-seeds.

Nuttige opdragte vir ’n eerste deurloop is:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Bespeur MBA-uitdrukkings wat as konstantes vermom is

’n Blykbaar invoerafhanklike byte-uitdrukking kan sy invoer heeltemal kanselleer. Nadat die tabelle daarvan onttrek is, evalueer die uitdrukking oor die volledige 8-bis-domein; ’n enkelvoudige uitsetstel bewys dat daardie byte konstant is, sonder om die omliggende toestandsmasjien te herwin.<sup>[[7]](#references)</sup>

```python
def mba(a, b, c, d, e, x):
    return ((((a | (~x & 0xff)) & c) +
             ((x | b) & d)) ^ e) & 0xff

decoded = bytearray()
for row in zip(A, B, C, D, E):
    outputs = {mba(*row, x) for x in range(256)}
    if len(outputs) != 1:
        raise ValueError("expression depends on x")
    decoded.append(outputs.pop())
print(decoded)
```

Behou die finale mask omdat die oorspronklike optelling byte-wydte-oorloop het. Vra vir ’n wyer domein ’n SMT solver of `f(x1) != f(x2)` bevredigbaar is vir twee simboliese invoere van dieselfde breedte: `unsat` bewys invariansie, terwyl `sat` ’n teenvoorbeeld lewer en beteken dat die invoer nie weggegooi kan word nie.<sup>[[7]](#references)</sup>

#### Herken omgewingsgebonde dekodering

Anti-analise-kontroles hoef nie ’n tak te neem of te crash nie. ’n Dekodeerder kan ’n sensorresultaat in ’n sleutelbis, ’n opaque-predicate-konstante of flattened-dispatcher-toestand meng, normaal voortgaan en geloofwaardige maar vals plaintext in ’n emulator produseer. Daarom is dit onvoldoende om slegs sigbare fouttakke te patch; volg data-afhanklikhede vanaf omgewingsondersoeke tot by die dekodeerdertoestand, vergelyk dieselfde slice op die egte toestel en emulator, en toets hoe die afdwinging van elke sensorresultaat die finale buffer verander.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is ’n praktiese MBA-simplifiseerder vir malware-analise en reversing van beskermde binaries. Dit klassifiseer die uitdrukking en stuur dit deur gespesialiseerde pyplyne, eerder as om een generiese herskryfpas op alles toe te pas.<sup>[[2]](#references)</sup>

Vinnige gebruik:

```bash
# Recover arithmetic from a logic-heavy MBA
cobra-cli --mba "(x&y)+(x|y)"
# x + y

# Preserve fixed-width wraparound semantics
cobra-cli --mba "(x&0xFF)+(x&0xFF00)" --bitwidth 16
# x

# Ask CoBRA to prove the rewrite with Z3
cobra-cli --mba "(a^b)+(a&b)+(a&b)" --verify
```

Useful cases:

- **Linear MBA**: CoBRA evalueer die uitdrukking op Boolean-insette, lei ’n handtekening af en laat verskeie herstelmetodes, soos pattern matching, ANF-omskakeling en koëffisiëntinterpolasie, teen mekaar meeding.
- **Semilinear MBA**: Atome met konstante maskers word herbou met bitverdelingsgebaseerde rekonstruksie, sodat gemaskerde streke korrek bly.
- **Polynomial/Mixed MBA**: Produkte word in kerne ontbind, en herhaalde subuitdrukkings kan na tydelike veranderlikes gelig word voordat die buitenste relasie vereenvoudig word.

Voorbeeld van ’n gemengde identiteit wat dikwels die moeite werd is om te probeer herwin:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dit kan vereenvoudig word tot:

```c
x * y
```

### Reverseer-notas

- Gebruik CoBRA verkieslik op **geligte IR-uitdrukkings** of decompiler-uitvoer nadat jy die presiese berekening geïsoleer het.
- Gebruik `--bitwidth` uitdruklik wanneer die uitdrukking van gemaskerde rekenkunde of nou registers kom.
- As jy ’n sterker bewysstap nodig het, kyk na die plaaslike Z3-notas hier:

{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA word ook as ’n **LLVM-pass-inprop** (`libCobraPass.so`) versprei. Dit is nuttig wanneer jy MBA-swaar LLVM IR wil normaliseer voordat jy latere ontledingspasses uitvoer.
- Residuele uitdrukkings met gemengde domeine waarin oordragte ’n rol speel, maar wat nie ondersteun word nie, moet beskou word as ’n teken om die oorspronklike uitdrukking te behou en die oordragpad met die hand te ontleed.

## Herstel van XOR-toestandbeheer-vloeiverplatting

’n OLLVM-styl verflatter kan die huidige basic-block-toestand in twee 64-bis-registers hou en dit met XOR by ’n dispatcher rekonstrueer. Elke oorspronklike blok skryf die paar vir sy volgende toestand en spring terug na die dispatcher. ’n Voorwaardelike blok kan `CMOVcc` gebruik om een helfte van die paar volgens CPU-vlae te vervang, so as jy net die sigbare vertakkingsinstruksies volg, mis jy die twee opvolgers. Anders as ’n indirekte-sprongdispatcher, kan hierdie vorm deurgaans direkte terugwaartse spronge gebruik.<sup>[[19]](#references)[[20]](#references)</sup>

Om die grafiek te herstel, identifiseer die dispatcher se vergelykingboom en die twee toestandregisters, koppel elke vergelykte XOR-toestand aan sy teikenblok, en spoor dan die skryfbewerkings na die registerpaar in elke oorspronklike blok na. Sluit vir voorwaardelike skryfbewerkings die vlae-instellende instruksie en albei `CMOVcc`-uitkomste in. Vervang elke blok se dispatcher-uitgang met sy opgeloste direkte opvolger of voorwaardelike vertakking; daarna is die dispatcher onbereikbaar sonder dat die binêre lêer gelap hoef te word. Dit is ’n volledige CFG-benadering; as net een decoder saak maak, kan die [nou uitvoeringsnit-werkvloei](#bypass-flattened-control-flow-with-a-narrow-execution-slice) hierbo vinniger wees.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) outomatiseer hierdie vorm in Binary Ninja. Kopieer `plugins/DispatchThis` na die Binary Ninja-gebruikersinpropgids en herbegin. Maak **Function Settings** in die betrokke funksie oop en kies `OLLVM_XOR_64`; as ontleding nie begin nie, gebruik **Analysis → Reanalyze All Functions**. Hierdie modus herskryf MLIL-beheervloeirande, nie lêergrepe nie, en het nie Z3 of die indirekte-sprongoplosser nodig nie. Dit is op Binary Ninja 5.3.9757+ getoets; dit verwyder nie die dooie toestandsskryfbewerkings per blok nie, so moenie dit met oorblywende aktiewe oorgange verwar nie.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Hierdie verduisteraar vervang programbewerkings met `mov`-gebaseerde instruksiereekse en gebruik sein-/uitsonderingshantering om die beheervloei te verander. Vir besonderhede:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Vir ondersteunde binêre lêers kan [demovfuscator](https://github.com/kirschju/demovfuscator) die resultaat deobfuskeer. Dit het verskeie afhanklikhede.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

En [installeer keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

As jy aan ’n **CTF** deelneem, kan hierdie omseiling om die **flag** te vind baie nuttig wees: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Om die **entry point** te vind, soek die funksies na `::main`, soos in:

![Vind ’n Rust entry point in Ghidra deur na funksiename met dubbelkolon main te soek](<../../images/image (1080).png>)

In hierdie geval is die binêre lêer authenticator genoem, so dit is redelik duidelik dat dit die interessante main-funksie is.\
As jy die **name** van die **funksies** ken wat geroep word, soek daarna op die **Internet** om meer oor hul **insette** en **uitsette** te wete te kom.

### Herstel van Rust-stringe uit ELF-firmware

In **Rust ELF**-binêre lêers word daar dikwels nie na baie statiese stringe verwys met C-styl NUL-terminerende pointers nie. ’n Algemene `rustc`-uitleg is ’n **pointer/lengte-tupel** binne **`.data.rel.ro`** wat na die werklike stringblok in **`.rodata`** wys:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Dit beteken dat `strings` of Ghidra se verstekontleding aangrensende stringe kan saamsmelt of kruisverwysings heeltemal kan miskyk.<sup>[[3]](#references)</sup>

Vinnige werkvloei:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Kry die virtuele adres en grootte van **`.rodata`**.
2. Enumereer **`.data.rel.ro`** een woord op ’n slag.
3. Behandel enige waarde binne die adresreeks van `.rodata` as ’n kandidaat-stringaanwyser.
4. Behandel die volgende woord as die kandidaat-lengte.
5. Pas geldigheidsfilters toe (byvoorbeeld, behou lengtes tussen **4** en **100** grepe).
6. Lees presies `length` grepe vanaf `.rodata` in plaas daarvan om tot by `0x00` te skandeer.

Minimale onttrekkerlogika:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Dit is veral nuttig wanneer firmware reverse-engineer word, omdat herwonne Rust-stringe dikwels **HTTP-roetes, RPC-name, logboodskappe, assertions, lêername, config-sleutels, command handlers en auth-verwante logika** openbaar.

As Ghidra hierdie stringe miskyk, voer ’n pasgemaakte script/plugin uit wat dieselfde heuristiek toepas en stringdata by die verwysde `.rodata`-offsets skep. Die gepubliseerde `rust-strings`- en `RustStrings.py`-nutsmiddels van Pen Test Partners is goeie verwysings om die idee vir ander **woordgroottes, endianiteit en afdeling-uitlegte** aan te pas.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Vir Delphi-gecompileerde binaries kan jy [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) gebruik.

As jy ’n Delphi-binary moet reverse-engineer, stel ek voor dat jy die IDA-plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) gebruik.

Druk **Alt+F7** in IDA om ’n Python-plugin te laai, en kies dan die plugin-lêer.

Hierdie plugin voer die binary uit en los funksiename dinamies op wanneer die ontfouting begin. Nadat die ontfouting begin het, druk weer die Start-knoppie (die groen een of f9), en ’n breakpoint sal aan die begin van die werklike kode tref.

As jy ’n knoppie in die grafiese toepassing druk, kan die debugger stop by die funksie wat deur daardie knoppie aangeroep word.

## Golang

Vir gewone Go-binaries kan [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) runtime-strukture herwin en funksiename in IDA verbeter. Laai die Python-plugin met **Alt+F7**.

As jy ’n Golang-binary moet reverse-engineer, stel ek voor dat jy die IDA-plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) gebruik.

Druk **Alt+F7** in IDA om ’n Python-plugin te laai, en kies dan die plugin-lêer.

Dit sal die name van die funksies oplos.

### Herwin metadata sonder die simbooltabel

’n Gestroopte Go-uitvoerbare lêer benodig steeds runtime-metadata om programtellers na funksies te karteer. [GoReSym](https://github.com/mandiant/GoReSym) vind en ontleed strukture soos `pclntab` en `moduledata` met behulp van kode wat van die Go-runtime afgelei is. Dit kan funksiegrense, name, bronpaaie, tipes en boubesonderhede herwin sonder om op die konvensionele simbooltabel staat te maak.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

’n Obfuskator kan daardie strukture bruikbaar laat terwyl dit die herstelde name vervang. Garble hash byvoorbeeld identifiseerders en pakketpaaie en verwyder bou-, module- en ontfoutingsinligting.<sup>[[12]](#references)</sup> Die geobfuskateerde pakkettoken moet konsekwent bly oor funksies uit daardie pakket heen. Groepeer funksies volgens die herhaalde token, lei een pakket af uit sy callees, stringe en API’s, en versprei dan daardie pakketetiket na die hele groep.<sup>[[13]](#references)</sup>

### Herstel Garble-name met GoResolver

[GoResolver](https://github.com/volexity/GoResolver) kombineer runtime-simboolonttrekking met die generering van skoon verwysings en die passing van beheervloeigrafieke (CFG’s). Gebruik hierdie volgorde:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifiseer die samestellerweergawe.** Probeer eers `BuildInfo` en ingebedde weergawe-stringe. As die obfuskator dit verwyder het, vergelyk dele van die gebundelde Go-runtime met weergawegespesifiseerde verwysingsruntimes. In Volexity se toetse was ongeveer `2%` van die runtime genoeg om groot Go-weergawes van mekaar te onderskei. Beskou dit as ’n empiriese optimalisering, nie ’n universele drempel nie.<sup>[[13]](#references)</sup>
2. **Bou passende verwysings.** Genereer skoon binaries vir die geïdentifiseerde Go-weergawe, teikenargitektuur en waarskynlike biblioteke. Deur die toolchain te laat ooreenstem, word CFG-verskille wat deur die samesteller gegenereer word, beperk.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Vergelyk funksies.** GoGrapher pas funksie-CFG’s en lewer genormaliseerde tellings van `0.0` tot `1.0`. Die passing van basiese blokke is gebaseer op ’n geweegde vergelyking van soortgelyke instruksies. Hoësekerheid-passings koppel gerandomiseerde funksies aan die skoon implementering. Swakker passings kan steeds ’n pakket of module identifiseer.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Valideer en voer in.** Bevestig voorgestelde name met oproepverwantskappe, konstantes, stringe en newe-effekte, en voer dan die JSON-verslag in met die GoResolver-inprop vir IDA of Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Installeer die toolchain en voer die gekombineerde onttrekker en grafiekpasser uit:<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

Die verstekdrempel vir betekenisvolle passing is `0.9`. Die `--extract`- en `--graph`-skakelaars kan enige van die stadiums afsonder, terwyl die verstek albei uitvoer omdat die herwonne runtime-metadata en CFG-bewyse mekaar aanvul.<sup>[[10]](#references)</sup> CFG-tellings is heuristies: inlining, bouvlae, argitektuur en verskille in biblioteekweergawes kan die grafiekvorm verander, dus moet onopgeloste funksies behou word eerder as om name met lae sekerheid af te dwing.<sup>[[13]](#references)</sup>

### Herwinning van die Go-stringtabel

Go-binaries plaas stringgrepe van elke gekoppelde pakket in een aaneenlopende tabel. Die inskrywings word nie met NUL beëindig nie, en runtime-strukture stel nie die tabel se basis of grootte bloot nie. Die samesteller orden inskrywings egter eers volgens lengte en dan alfabeties, oor bedryfstelsels en argitekture heen. Nadat ’n inskrywing gevind is, kan ’n ontleder dus aangrensende inskrywings deurloop en data-kruisverwysings gebruik om stringe aan kode te koppel.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) outomatiseer hierdie werkvloei in IDA Pro en Ghidra. Laat outo-analise eers voltooi, want die plugin maak staat op kruisverwysings in datasegmente. Die verstekanker is die runtime-string `entersyscall`, waarna dit in enige rigting kan skandeer, die herwonne stringe in die databasis kan definieer en ’n JSON-kartering van stringe na verwysende funksies kan uitvoer.<sup>[[14]](#references)</sup>

Filtreer die verslag volgens die pakket van die verwysende funksie om toepassing- of malware-kode van gekoppelde biblioteekgeraas te skei. Hierdie tegniek kan nie letterlike stringe herwin wat deur obfuskasie vernietig is nie, soos Garble se `-literals`-transformasie. Dit kan steeds runtime-stringe organiseer wat nie geobfuskeer is nie.<sup>[[14]](#references)[[15]](#references)</sup>

### Herwinning van Go-runtime-tipes

Go sluit runtime-tipe-inligting in wat deur kenmerke soos garbage collection gebruik word. Wanneer bouinligting verwyder is of die disassembler nie hierdie metadata ontleed nie, kan dit lyk asof instruksies willekeurige data-adresse laai, terwyl die teikenstreek ongetipeer bly. Deur die metadata te herwin, word hierdie adresse leesbare tipeverwysings, wat dit makliker maak om pakketvermoëns te verstaan.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) kan simbole onttrek en runtime-tipes in ’n JSON-verslag ontleed. Die huidige CLI gebruik die `resolve`-subopdrag:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Die `-y`/`--types`-opsie aktiveer tipe-ontleding. Voer die verslag in met GoResolver se IDA Pro- of Ghidra-inprop om die herstelde tipes te definieer en hul verwysings in die ontledingsdatabasis toe te pas. In die verslagformaat wat met hierdie funksie bekendgestel is, bly die RTTI-adres en herstelde-tipes-lede null as `-y` weggelaat word.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver ondersteun PE-, ELF- en Mach-O-voorbeelde vir x86, AMD64, ARM en ARM64, dus geld dieselfde werkvloei vir Go-binêre lêers van Windows, Linux en macOS.<sup>[[10]](#references)</sup>

## Saamgestelde Python

Op hierdie bladsy kan jy vind hoe om die Python-kode uit ’n ELF/EXE-binêre lêer met saamgestelde Python te kry:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

As jy die **binêre lêer** van ’n GBA-speletjie kry, kan jy verskillende tools gebruik om dit te **emuleer** en **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Laai die debug-weergawe af_) - Bevat ’n debugger met ’n koppelvlak
- [**mgba** ](https://mgba.io)- Bevat ’n CLI-debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-inprop
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-inprop

In [**no$gba**](https://problemkaputt.de/gba.htm), onder _**Options --> Emulation Setup --> Controls**_** ** kan jy sien hoe om die Game Boy Advance-**knoppies** te druk

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Wanneer dit gedruk word, **het elke sleutel ’n waarde** om dit te identifiseer:

```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```

Dus, in hierdie soort program sal die interessante deel wees **hoe die program die gebruiker-invoer hanteer**. By adres **0x4000130** vind jy die algemeen voorkomende funksie: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

In die vorige afbeelding kan jy sien dat die funksie vanaf **FUN_080015a8** geroep word (adresse: _0x080015fa_ en _0x080017ac_).

In daardie funksie, ná ’n paar init-bewerkings (wat nie belangrik is nie):

```c
void FUN_080015a8(void)

{
  ushort uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  ushort uVar4;
  int iVar5;
  ushort *puVar6;
  undefined *local_2c;

  DISPCNT = 0x1140;
  FUN_08000a74();
  FUN_08000ce4(1);
  DISPCNT = 0x404;
  FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
  FUN_08000354(&DAT_030000dc,0x3c);
  uVar4 = DAT_030004d8;
```

Hierdie kode is gevind:

```c
  do {
    DAT_030004da = uVar4; //This is the last key pressed
    DAT_030004d8 = KEYINPUT | 0xfc00;
    puVar6 = &DAT_0200b03c;
    uVar4 = DAT_030004d8;
    do {
      uVar2 = DAT_030004dc;
      uVar1 = *puVar6;
      if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```

Die laaste if kontroleer of **`uVar4`** onder die **laaste sleutels** is en nie die huidige sleutel is nie; dit beteken ook dat ’n knoppie losgelaat word (die huidige sleutel word in **`uVar1`** gestoor).

```c
        if (uVar1 == 4) {
          DAT_030000d4 = 0;
          uVar3 = FUN_08001c24(DAT_030004dc);
          FUN_08001868(uVar2,0,uVar3);
          DAT_05000000 = 0x1483;
          FUN_08001844(&DAT_0200ba18);
          FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
          DAT_030000d8 = 0;
          uVar4 = DAT_030004d8;
        }
        else {
          if (uVar1 == 8) {
            if (DAT_030000d8 == 0xf3) {
              DISPCNT = 0x404;
              FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
              FUN_08000354(&DAT_030000dc,0x3c);
              uVar4 = DAT_030004d8;
            }
          }
          else {
            if (DAT_030000d4 < 8) {
              DAT_030000d4 = DAT_030000d4 + 1;
              FUN_08000864();
              if (uVar1 == 0x10) {
                DAT_030000d8 = DAT_030000d8 + 0x3a;
```

In die vorige kode kan jy sien dat ons **uVar1** (die plek waar die **waarde van die ingedrukte knoppie** is) met sommige waardes vergelyk:

- Eerstens word dit met die **waarde 4** (**SELECT**-knoppie) vergelyk: In die uitdaging maak hierdie knoppie die skerm skoon.
- Dan word die waarde met **8** (die **START**-knoppie) vergelyk; in hierdie uitdaging kontroleer daardie pad of die ingevoerde kode geldig is.
  - In hierdie geval word die var **`DAT_030000d8`** met 0xf3 vergelyk, en as die waardes ooreenstem, word sekere kode uitgevoer.
- In alle ander gevalle word ’n teller (`DAT_030000d4`) nagegaan en verhoog.\
  Solank die teller kleiner as 8 is, word die waardes van die ingedrukte knoppies in `DAT_030000d8` bymekaargetel.

Dus moes jy in hierdie uitdaging, met kennis van die knoppiewaardes, **’n kombinasie korter as 8 knoppies indruk waarvan die som 0xf3 is.**

**Verwysing vir hierdie tutoriaal:** [argiefweergawe van Nostalgia-uitdagingskrywe](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursusse

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binêre de- obfuskering)

## References

- [1] [Vereenvoudiging van MBA-obfuskering met CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA-bewaarplek](https://github.com/trailofbits/CoBRA)
- [3] [Dekodering van Rust-stringe - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA-reversing-tutoriaal (argiefweergawe)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Om AI-ondersteunde Reverse Engineering te verslaan, of dit ten minste te probeer](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [’n Benadering om beheervloeigrafieke te vergelyk op grond van basiese-blokpassing](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver-bewaarplek](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble-obfuskeringsmeganisme](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Gebruik van beheervloeigraaf-ooreenkomste om Golang-binêre lêers outomaties te de-obfuskereer](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor-bewaarplek](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Opdaterings aan Volexity se Golang-nutsgoed](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [REA-ontleding van bestuurde kode](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI- en Bewysgids](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Werkvloei vir die ontflattening van Binary Ninja-beheervloei](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF-zero-day-inbraak, Java-laaier, webshell en AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementering van die IDA-bridgebediener](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementering van die Ghidra-bridgebediener](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) bind aan die jokeradres](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Godot-nutsdingstel vir Reverse Engineering](https://github.com/figurophobia/gore)
- [26] [gore-implementering van sleutelherwinning](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [gore-formaat vir geënkripteerde blobs](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [gore-implementering van opdragte en herstel](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
