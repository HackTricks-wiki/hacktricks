# Reversing-nutsgoed en basiese metodes

{{#include ../../banners/hacktricks-training.md}}

## ImGui-gebaseerde reversing-nutsgoed

Sagteware:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows-kernelfoutopsporing

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm-decompiler / Wat-kompiler

Aanlyn:

- Gebruik [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) om van wasm (binêr) na wat (leesbare teks) te **decompile**
- Gebruik [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) om van wat na wasm te **compile**
- Jy kan ook [web-wasmdec](https://wwwg.github.io/web-wasmdec/) probeer vir decompilering.

Sagteware:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8-gecachede bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Gevirtualiseerde payloads en pasgemaakte VMs

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET-decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is ’n decompiler wat **verskeie formate decompileer en ondersoek**, insluitend **libraries** (.dll), **Windows-metadata-lêers** (.winmd) en **executables** (.exe). Nadat ’n assembly gedecompileer is, kan dit as ’n Visual Studio-projek (.csproj) gestoor word.

Die voordeel hiervan is dat hierdie proses tyd kan bespaar wanneer verlore bronkode uit ’n legacy-assembly herstel moet word. Verder bied dotPeek handige navigasie deur die gedecompileerde kode, wat dit een van die perfekte nutsgoed vir **Xamarin-algoritme-analise** maak.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Met ’n omvattende add-in-model en ’n API wat die nutsding uitbrei om aan jou presiese behoeftes te voldoen, bespaar .NET Reflector tyd en vereenvoudig dit ontwikkeling. Kom ons kyk na die talle reverse-engineering-dienste wat hierdie nutsding bied:

- Gee insig in hoe data deur ’n library of komponent vloei
- Gee insig in die implementering en gebruik van .NET-tale en frameworks
- Vind ongedokumenteerde en onblootgestelde funksionaliteit om meer uit die gebruikte APIs en tegnologieë te haal.
- Vind afhanklikhede en verskillende assemblies
- Vind die presiese ligging van foute in jou kode, derdeparty-komponente en libraries.
- Ontfout die bronkode van al die .NET-kode waarmee jy werk.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-inprop vir Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Jy kan dit op enige OS gebruik (jy kan dit direk vanaf VSCode installeer; jy hoef nie die git af te laai nie. Klik op **Extensions** en **soek na ILSpy**).\
As jy weer wil **decompile**, **modify** en **recompile**, kan jy [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) of ’n aktief onderhoude fork daarvan, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), gebruik. (**Regskliek -> Modify Method** om iets binne ’n funksie te verander).

### Uitvoeringsvrye bestuurde inspeksie met REA

**REA** kan PE/CLI-metadata en CIL inspekteer sonder om die assembly te laai. Begin met die artefak se identiteit en inspekteer dan lede en verklaarde native-grense; dit is nuttig wanneer verdagte oproepe nagegaan word voordat ’n decompiler gebruik word of die program uitgevoer word.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Vir weergawe-diffing gebruik `compare_managed_members` rou CIL-/handtekening-identiteit en vingerafdrukke van gedekodeerde instruksies, eerder as om metadata-tokens as stabiel tussen builds te beskou. ’n P/Invoke-deklarasie bewys nie dat native code uitgevoer is nie; `verify_managed_native_boundaries` benodig ’n ooreenstemmende native export of funksie-Evidence om daardie grens na te gaan. Bewaar die artifact-digest, MVID en onopgeloste mappings saam met die resultaat.<sup>[[17]](#references)</sup>

### DNSpy Logging

Om **DNSpy sekere inligting na ’n lêer te laat log**, kan jy hierdie kodebrokkie gebruik:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Om kode met DNSpy te debug, moet jy:

Verander eers die **Assembly attributes** wat met **debugging** verband hou:

![DNSpy Logging - DNSpy Debugging: Verander eers die Assembly attributes wat met debugging verband hou](<../../images/image (973).png>)

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

Dit is nodig omdat verskeie **optimaliserings** tydens **runtime** op die kode toegepas sal word as jy dit nie doen nie, en dit kan gebeur dat ’n **break-point nooit bereik word nie** of dat sommige **veranderlikes nie bestaan nie** terwyl jy debug.

As jou .NET-toepassing dan deur **IIS** **uitgevoer** word, kan jy dit met die volgende **herbegin**:

```
iisreset /noforce
```

Dan moet jy, om te begin ontfout, al die oop lêers sluit en **Attach to Process...** in die **Debug Tab** kies:

![DNSpy Logging - DNSpy Debugging: Dan moet jy, om te begin ontfout, al die oop lêers sluit en Attach to Process in die Debug Tab kies](<../../images/image (318).png>)

Kies dan **w3wp.exe** om aan die **IIS server** te koppel en klik **attach**:

![DNSpy Logging - DNSpy Debugging: Kies dan w3wp.exe om aan die IIS server te koppel en klik attach](<../../images/image (113).png>)

Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers **Debug >> Break All** en klik dan **_Debug >> Windows >> Modules_**:

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers op Debug Break All en klik dan op Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers op Debug Break All en klik dan op Debug Windows Modules](<../../images/image (834).png>)

Klik op enige module in **Modules** en kies **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Klik op enige module in Modules en kies Open All Modules](<../../images/image (922).png>)

Regsklik op enige module in **Assembly Explorer** en klik **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Regsklik op enige module in Assembly Explorer en klik Sort Assemblies](<../../images/image (339).png>)

## Java-decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Ontfouting van DLL's

### Met IDA

- **Laai rundll32** (64bits in C:\Windows\System32\rundll32.exe en 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Kies die **Windbg**-ontfouter
- Kies "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Kies " Suspend on library load/unload "](<../../images/image (868).png>)

- Stel die **parameters** vir die uitvoering op deur die **pad na die DLL** en die funksie wat jy wil aanroep, in te voer:

![Debugging DLLs - Using IDA: Stel die parameters vir die uitvoering op deur die pad na die DLL en die funksie wat jy wil aanroep, in te voer](<../../images/image (704).png>)

Wanneer jy dan begin ontfout, **sal die uitvoering stop wanneer elke DLL gelaai word**. Wanneer rundll32 jou DLL laai, sal die uitvoering dus stop.

Hierdie metode stop by modulelaai-gebeurtenisse, maar dit is minder direk as met die x64dbg-werkvloei hieronder om die toegangspunt van die gelaaide DLL te bereik.

### Met x64dbg/x32dbg

- **Laai rundll32** (64bits in C:\Windows\System32\rundll32.exe en 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Verander die Command Line** ( _File --> Change Command Line_ ) en stel die pad na die dll en die funksie wat jy wil aanroep in, byvoorbeeld: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Verander _Options --> Settings_ en kies "**DLL Entry**".
- **Begin dan die uitvoering**; die ontfouter sal by elke dll main stop, en op ’n sekere punt sal jy **by die DLL Entry van jou dll stop**. Soek van daar af na die plekke waar jy ’n breakpoint wil plaas.

Let daarop dat wanneer die uitvoering om enige rede in win64dbg stop, jy kan sien **in watter kode jy is** deur bo-aan die win64dbg-venster te kyk:

![Using IDA - Using x64dbg/x32dbg: Let daarop dat wanneer die uitvoering om enige rede in win64dbg stop, jy kan sien in watter kode jy is deur bo-aan die win64dbg-venster te kyk](<../../images/image (842).png>)

Hierdie aanduiding bevestig wanneer die uitvoering binne die DLL is wat jy wil ontfout.

## GUI-toepassings / Videospeletjies

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is ’n nuttige program om te vind waar belangrike waardes in die geheue van ’n lopende speletjie gestoor word, en om dit te verander. Meer inligting by:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is ’n front-end-/reverse-engineering-hulpmiddel vir die GNU Project Debugger (GDB), met die fokus op speletjies. Dit kan egter vir enigiets wat met reverse engineering verband hou, gebruik word.

[**Decompiler Explorer**](https://dogbolt.org/) is ’n web-front-end vir ’n aantal decompilers. Met hierdie webdiens kan jy die uitvoer van verskillende decompilers op klein uitvoerbare lêers vergelyk.

## Ondersoek van native kode met REA, gesteun deur bewyse

**REA** bied toegang tot Hopper-, Ghidra- en IDA-ontleding via CLI en MCP. Dit vereis Node.js 22.x (ten minste 22.19), 24.x (ten minste 24.11) of 26+, plus npm. Stel eers ’n bestaande native provider op; kyk na `rea providers --json` en kies ’n provider uitdruklik wanneer meer as een die teiken ondersteun. Gebruik hieronder ’n waargenome funksienaam of adres uit die inventaris in die plek van `0x1000`.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Begin by ’n feature string of simbool, volg verwysings en callers, en inspekteer dan die geselekteerde funksiedossier en pseudocode met `rea decompile`. REA bind ’n sessie aan die geselekteerde provider, eerder as om dit stilweg ná ’n fout te vervang. Vir herhaalbare navrae hergebruik `--snapshot PATH` slegs bypassende artifact-bytes, provider, instellings, bewerking en parameters; ’n snapshot is ’n plaaslike cache, nie ’n gestoorde provider-databasis nie. Bewaar die teruggestuurde Evidence en eksplisiete onbekendes, eerder as om afgeleide paaie of decompiler-teks as oorspronklike bronkode te behandel.<sup>[[16]](#references)[[18]](#references)</sup>

Vir JavaScript/Electron entry points wat na native add-ons lei, sien [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging van ’n shellcode met blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) allokeer die **shellcode**, druk sy **geheue-adres** uit en laat die uitvoering wag.\
Koppel ’n debugger soos IDA of x64dbg, stel ’n breakpoint by die uitgedrukte adres en hervat uitvoering om die shellcode te debug.

Die GitHub-releases-bladsy bevat zip-lêers met die gekompileerde releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Jy kan ’n effens aangepaste weergawe van Blobrunner by die volgende skakel vind. Om dit te kompileer, **skep net ’n C/C++-projek in Visual Studio Code, kopieer en plak die kode en bou dit**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging van ’n shellcode met jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) is soortgelyk aan BlobRunner. Dit allokeer die shellcode en betree ’n oneindige lus. Koppel die debugger, hervat vir **2–5 sekondes**, breek binne daardie lus en stap na die volgende call wat uitvoering na die geallokeerde shellcode oordra.

![Debugger gepouseer in jmp2it se oneindige lus, onmiddellik voor die call na die geallokeerde shellcode](<../../images/image (509).png>)

Jy kan ’n gekompileerde weergawe van [jmp2it op die releases-bladsy aflaai](https://github.com/adamkramer/jmp2it/releases/).

### Debugging van shellcode met Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is die GUI van radare. Met Cutter kan jy die shellcode emuleer en dit dinamies inspekteer.

Let daarop dat Cutter jou toelaat om “Open File” en “Open Shellcode” te kies. In my geval het dit die shellcode korrek gedekompileer toe ek dit as ’n lêer oopgemaak het, maar nie toe ek dit as shellcode oopgemaak het nie:

![Cutter wys verskillende ontledingsresultate wanneer dieselfde grepe as ’n lêer of as shellcode oopgemaak word](<../../images/image (562).png>)

Om die emulasie te begin op die plek waar jy wil, stel ’n bp daar; dit lyk of Cutter dan die emulasie outomaties van daar af begin:

![Stel ’n breakpoint by die verlangde shellcode-entry voordat Cutter-emulasie begin](<../../images/image (589).png>)

![Cutter-emulator gepouseer by die geselekteerde shellcode-breakpoint](<../../images/image (387).png>)

Jy kan byvoorbeeld die stack in ’n hex dump sien:

![Bekyk die geëmuleerde shellcode-stack in Cutter se hex dump](<../../images/image (186).png>)

### Deobfuscating van shellcode en vind van uitgevoerde funksies

Jy behoort [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) te probeer.\
Dit sal jou dinge vertel soos **watter funksies** die shellcode gebruik en of die shellcode homself in die geheue **decodeer**.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg het ook ’n grafiese lanseerder waarmee jy die gewenste opsies kan kies en die shellcode kan uitvoer

![scDbg se grafiese lanseerder om shellcode-emulasie- en nasporingsopsies te kies](<../../images/image (258).png>)

Die opsie **Create Dump** sal die finale shellcode stoor as enige veranderinge dinamies in die geheue aan die shellcode aangebring word (nuttig om die gedekodeerde shellcode af te laai). **start offset** kan nuttig wees om die shellcode by ’n spesifieke offset te begin uitvoer. Die opsie **Debug Shell** is nuttig om die shellcode met die scDbg-terminaal te ontfout (ek vind egter enige van die opsies wat vroeër verduidelik is, beter hiervoor, aangesien jy Ida of x64dbg kan gebruik).

### Disassemblering met CyberChef

Laai jou shellcode-lêer as invoer op en gebruik die volgende resep om dit te dekompileer: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)**-obfuscation verberg eenvoudige uitdrukkings soos `x + y` agter formules wat rekenkundige operateurs (`+`, `-`, `*`) en bitwyse operateurs (`&`, `|`, `^`, `~`, verskuiwings) meng. Die belangrike punt is dat hierdie identiteite gewoonlik slegs korrek is met **vaste-breedte-modulêre rekenkunde**, dus maak oordragte en oorlope saak:

```c
(x ^ y) + 2 * (x & y) == x + y
```

As jy hierdie soort uitdrukking met generiese algebranutsmiddels vereenvoudig, kan jy maklik ’n verkeerde resultaat kry omdat die bitwydte-semantiek geïgnoreer is.<sup>[[1]](#references)</sup>

### Praktiese werkvloei

1. **Behou die oorspronklike bitwydte** van die geligte kode/IR/decompiler-uitvoer (`8/16/32/64` bits).
2. **Klassifiseer die uitdrukking** voordat jy dit probeer vereenvoudig:
   - **Lineêr**: geweegde somme van bitwise-atome
   - **Semilineêr**: lineêr plus konstante maskers soos `x & 0xFF`
   - **Polinoom**: produkte kom voor
   - **Gemeng**: produkte en bitwise-logika is ineengevleg, dikwels met herhaalde subuitdrukkings
3. **Verifieer elke kandidaat-herskrywing** met ewekansige toetsing of ’n SMT-bewys. As die ekwivalensie nie bewys kan word nie, behou eerder die oorspronklike uitdrukking as om te raai.

### Omseil afgeplatte beheervloei met ’n nou uitvoeringsnit

Om die volledige beheervloeigrafiek te herwin, is dikwels onnodig. Met control-flow flattening, ondeursigtige predikate, groot dispatchers of kode wat swaar op MBA steun, volg verwysings vanaf geënkripteerde blobs en uitvoerbuffers na die kleinste roetine wat hulle transformeer. Herproduseer dan net daardie datavloeisnit, of voer dit onafhanklik uit; die dispatcher is nie deel van die vereiste oplossing as die relevante toestand direk geïnisialiseer kan word nie.<sup>[[7]](#references)</sup>

’n Praktiese werkvloei is:<sup>[[7]](#references)</sup>

1. Maak ’n inventaris van uitvoerbare en data-afdelings, relocations en kruisverwysings. Dump kandidaatabelle uit `.rodata` en behou hul grepevolgorde en elementwydte.
2. Identifiseer die laaste roetine wat na die gewone teks of uitvoerbuffer skryf. Teken sy insette, verwysde tabelle, ingevoerde oproepe en vereiste globale toestand aan.
3. Lig net daardie bewerkings in ’n Python-model met vaste breedtes. As die snit steeds van te veel toestand afhanklik is, roep die roetine onder Unicorn, QEMU of ’n debugger aan en haak irrelevante invoere in plaas daarvan om die hele program na te boots.
4. Bevestig dat die onttrekker sy uitvoer werklik uit die verskafte binary aflei: verwyder stil terugvalopsies, soek daarin na ingebedde antwoorde en voer dit uit teen ongeziene builds met veranderde stringe, sleutels, identifiseerders, uitlegte en obfuskasiesade.

Nuttige opdragte vir ’n eerste ondersoek is:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Bespeur MBA-uitdrukkings wat as konstantes vermom is

’n Oënskynlik insetafhanklike byte-uitdrukking kan sy inset heeltemal kanselleer. Nadat jy sy tabelle onttrek het, evalueer die uitdrukking oor die volledige 8-bis-domein; ’n enkelvoudige uitsetversameling bewys dat daardie byte konstant is, sonder om die omliggende toestandsmasjien te herwin.<sup>[[7]](#references)</sup>

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

Keep die finale masker, omdat die oorspronklike optelling byte-wydte-oorloop het. Vra vir ’n wyer domein ’n SMT-solver of `f(x1) != f(x2)` bevredigbaar is vir twee simboliese invoere met dieselfde wydte: `unsat` bewys invariansie, terwyl `sat` ’n teenvoorbeeld gee en beteken dat die invoer nie weggegooi kan word nie.<sup>[[7]](#references)</sup>

#### Herken omgewingsgebonde dekodering

Anti-analise-kontroles hoef nie te vertak of te crash nie. ’n Decoder kan ’n sensorresultaat in ’n sleutelbis, ’n opaque-predicate-konstante of die toestand van ’n flattened dispatcher inmeng, normaal voortgaan en geloofwaardige maar onjuiste plaintext in ’n emulator lewer. Daarom is dit nie genoeg om slegs sigbare foutvertakkings te patch nie; volg die data-afhanklikhede van omgewingsondersoeke tot by die decoder-toestand, vergelyk dieselfde snit op die egte toestel en in die emulator, en toets hoe die afdwing van elke sensorresultaat die finale buffer verander.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is ’n praktiese MBA-vereenvoudiger vir wanware-analise en reversing van beskermde binaries. Dit klassifiseer die uitdrukking en stuur dit deur gespesialiseerde pyplyne, eerder as om een generiese herskryfpas op alles toe te pas.<sup>[[2]](#references)</sup>

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

Nuttige gevalle:

- **Linear MBA**: CoBRA evalueer die uitdrukking op Booleaanse invoere, lei ’n handtekening af en laat verskeie herstelmetodes teen mekaar meeding, soos patroonpassing, ANF-omskakeling en koëffisiëntinterpolasie.
- **Semilinear MBA**: konstante-gemaskerde atome word met behulp van bitgepartisioneerde rekonstruksie herbou, sodat gemaskerde streke korrek bly.
- **Polynomial/Mixed MBA**: produkte word in kerne opgebreek, en herhaalde subuitdrukkings kan in tydelike veranderlikes geplaas word voordat die buitenste relasie vereenvoudig word.

Voorbeeld van ’n gemengde identiteit wat dikwels die moeite werd is om te probeer herwin:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dit kan vereenvoudig word tot:

```c
x * y
```

### Aantekeninge oor reverse engineering

- Verkies om CoBRA op **lifted IR expressions** of decompiler-uitvoer te laat loop nadat jy die presiese berekening geïsoleer het.
- Gebruik `--bitwidth` uitdruklik wanneer die uitdrukking van gemaskerde rekenkunde of smal registers afkomstig is.
- As jy ’n sterker bewysstap nodig het, raadpleeg die plaaslike Z3-aantekeninge hier:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA word ook as ’n **LLVM pass plugin** (`libCobraPass.so`) versprei. Dit is nuttig wanneer jy MBA-swaar LLVM IR wil normaliseer voor latere ontledingspasses.
- Ongesteunde carry-sensitiewe gemengde-domein-residue moet beskou word as ’n aanduiding om die oorspronklike uitdrukking te behou en die carry-pad met die hand te ontleed.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Hierdie obfuscator vervang programbewerkings met `mov`-gebaseerde instruksievolgordes en gebruik sein-/uitsonderingshantering om control flow te verander. Vir meer besonderhede:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Vir ondersteunde binaries kan [demovfuscator](https://github.com/kirschju/demovfuscator) die resultaat deobfuscate. Dit het verskeie afhanklikhede.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

En [installeer keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

As jy aan ’n **CTF deelneem, kan hierdie ompad om die vlag te vind** baie nuttig wees: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Om die **entry point** te vind, soek na die funksies met `::main`, soos in:

![Vind ’n Rust entry point in Ghidra deur funksiename vir dubbelkolon main te soek](<../../images/image (1080).png>)

In hierdie geval is die binary authenticator genoem, so dit is redelik duidelik dat dit die interessante main-funksie is.\
Met die **name** van die **funksies** wat geroep word, soek daarna op die **Internet** om meer oor hul **insette** en **uitsette** te leer.

### Herwinning van Rust-tekenstringe uit ELF-firmware

In **Rust ELF**-binaries word daar dikwels nie na baie statiese tekenstringe verwys met C-styl NUL-terminerende wysers nie. ’n Algemene `rustc`-uitleg is ’n **wyser/lengte-tupel** binne **`.data.rel.ro`** wat na die werklike tekenstringblok in **`.rodata`** wys:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Dit beteken dat `strings` of Ghidra se verstekontleding aangrensende strings kan saamsmelt of kruisverwysings heeltemal kan miskyk.<sup>[[3]](#references)</sup>

Vinnige werkvloei:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Kry die virtuele adres en grootte van **`.rodata`**.
2. Enumereer **`.data.rel.ro`** woord vir woord.
3. Behandel enige waarde binne die adresreeks van `.rodata` as ’n kandidaat-stringwyser.
4. Behandel die volgende woord as die kandidaat-lengte.
5. Pas gesonde-verstand-filters toe (hou byvoorbeeld lengtes tussen **4** en **100** grepe).
6. Lees presies `length` grepe vanaf `.rodata` in plaas daarvan om te skandeer totdat `0x00` voorkom.

Minimale onttrekkingslogika:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Dit is veral nuttig vir firmware reversing, omdat herstelde Rust strings dikwels **HTTP-roetes, RPC-name, logboodskappe, assertions, lêername, config-sleutels, command-handlers en auth-verwante logika** onthul.

As Ghidra daardie strings mis, voer ’n pasgemaakte script/plugin uit wat dieselfde heuristiek toepas en string-data by die verwysde `.rodata`-offsets skep. Die gepubliseerde `rust-strings`- en `RustStrings.py`-tools van Pen Test Partners is goeie verwysings om die idee vir ander **woordgroottes, endianness en seksie-uitlegte** aan te pas.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Vir Delphi-gecompileerde binaries kan jy [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) gebruik.

As jy ’n Delphi-binary moet reverse, stel ek voor dat jy die IDA-plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) gebruik.

Druk **Alt+F7** in IDA om ’n Python-plugin te laai, en kies dan die plugin-lêer.

Hierdie plugin sal die binary uitvoer en funksiename dinamies aan die begin van die debugging oplos. Nadat die debugging begin het, druk weer die Start-knoppie (die groen een of f9), en ’n breakpoint sal aan die begin van die werklike kode tref.

As jy ’n knoppie in die grafiese toepassing druk, kan die debugger by die funksie stop wat deur daardie knoppie opgeroep word.

## Golang

Vir gewone Go-binaries kan [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) runtime-strukture herstel en funksiename in IDA verbeter. Laai die Python-plugin met **Alt+F7**.

As jy ’n Golang-binary moet reverse, stel ek voor dat jy die IDA-plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) gebruik.

Druk **Alt+F7** in IDA om ’n Python-plugin te laai, en kies dan die plugin-lêer.

Dit sal die name van die funksies oplos.

### Herstel metadata sonder die simbooltabel

’n Gestroopte Go-uitvoerbare lêer benodig steeds runtime-metadata om programtellers aan funksies te koppel. [GoReSym](https://github.com/mandiant/GoReSym) vind en ontleed strukture soos `pclntab` en `moduledata` deur kode te gebruik wat van die Go-runtime afgelei is. Dit kan funksiegrense, name, bronpaaie, tipes en bou-inligting herstel sonder om op die konvensionele simbooltabel staat te maak.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

'n Obfuscator kan daardie strukture bruikbaar laat terwyl die herstelde name vervang word. Garble has byvoorbeeld identifiseerders en pakketpaaie en verwyder bou-, module- en ontfoutinligting.<sup>[[12]](#references)</sup> Die verdoeselde pakkettoken moet konsekwent bly oor funksies uit daardie pakket. Groepeer funksies volgens die herhaalde token, lei een pakket af uit sy callees, stringe en API's, en propageer dan daardie pakketetiket na die hele groep.<sup>[[13]](#references)</sup>

### Herstel Garble-name met GoResolver

[GoResolver](https://github.com/volexity/GoResolver) kombineer runtime-simboolonttrekking met skoon verwysingsgenerering en beheer-vloeigrafiek- (CFG-)passing. Gebruik hierdie volgorde:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifiseer die samestellerweergawe.** Probeer eers `BuildInfo` en ingebedde weergawe-stringe. As die obfuscator dit verwyder het, vergelyk dele van die gebundelde Go-runtime met weergawe-spesifieke verwysingsruntimes. In Volexity se toetse was ongeveer `2%` van die runtime genoeg om hoofweergawes van Go te onderskei. Beskou dit as 'n empiriese optimalisering, nie 'n universele drempel nie.<sup>[[13]](#references)</sup>
2. **Bou gepaste verwysings.** Genereer skoon binaries vir die geïdentifiseerde Go-weergawe, teikenargitektuur en waarskynlike libraries. Deur die toolchain te pas, verminder jy CFG-verskille wat deur die samesteller gegenereer word.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Vergelyk funksies.** GoGrapher pas funksie-CFG's en lewer genormaliseerde tellings van `0.0` tot `1.0`. Die passing van basiese blokke is gebaseer op 'n geweegde vergelyking van soortgelyke instruksies. Passings met hoë sekerheid koppel ewekansig benoemde funksies aan die skoon implementering. Swakker passings kan steeds 'n pakket of module identifiseer.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
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

Die verstekdrempel vir betekenisvolle passing is `0.9`. Die `--extract`- en `--graph`-skakelaars kan elke stadium afsonderlik uitvoer, terwyl die verstek albei uitvoer omdat die herstelde runtime-metadata en CFG-bewyse mekaar aanvul.<sup>[[10]](#references)</sup> CFG-tellings is heuristies: inlining, bouvlae, argitektuur en verskille tussen biblioteekweergawes kan die grafiekvorm verander, dus moet onopgeloste funksies behoue bly eerder as om name met lae vertroue af te dwing.<sup>[[13]](#references)</sup>

### Herstel van die Go-stringtabel

Go-binêre lêers plaas stringgrepe van elke gekoppelde pakket in een aaneenlopende tabel. Die inskrywings is nie NUL-beëindig nie, en runtime-strukture stel nie die tabel se basisadres of grootte bloot nie. Die samesteller orden inskrywings egter eers volgens lengte en dan alfabeties oor bedryfstelsels en argitekture heen. Nadat ’n inskrywing gevind is, kan ’n ontleder dus aangrensende inskrywings deurloop en data-kruisverwysings gebruik om stringe met kode te assosieer.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) outomatiseer hierdie werkvloei in IDA Pro en Ghidra. Laat die outomatiese ontleding eers klaarmaak, aangesien die inprop op kruisverwysings in die datasegment staatmaak. Die verstekanker is die runtime-string `entersyscall`; daarna kan dit in enige rigting skandeer, die herstelde stringe in die databasis definieer en ’n JSON-toewysing van stringe aan verwysende funksies uitvoer.<sup>[[14]](#references)</sup>

Filtreer die verslag volgens die pakket van die verwysende funksie om toepassings- of malware-kode van gekoppelde biblioteekgeraas te skei. Hierdie tegniek kan nie letterlike stringe herstel wat deur obfuskering vernietig is nie, soos Garble se `-literals`-transformasie. Dit kan steeds runtime-stringe organiseer wat nie geobfuskateer is nie.<sup>[[14]](#references)[[15]](#references)</sup>

### Herstel van Go-runtime-tipes

Go sluit runtime-tipe-inligting in wat deur kenmerke soos vullisversameling gebruik word. Wanneer boubesonderhede verwyder is of die disassembler nie hierdie metadata ontleed nie, kan dit lyk asof instruksies arbitrêre data-adresse laai, en bly die teikengebied ongetipeer. Deur die metadata te herstel, word hierdie adresse leesbare tipeverwysings en word dit makliker om pakketvermoëns te verstaan.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) kan simbole onttrek en runtime-tipes in ’n JSON-verslag ontleed. Die huidige CLI gebruik die `resolve`-subopdrag:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Die `-y`/`--types`-opsie aktiveer tipeontleding. Voer die verslag in met GoResolver se IDA Pro- of Ghidra-plugin om die herwonne tipes te definieer en hul verwysings in die ontledingsdatabasis toe te pas. In die verslagformaat wat met hierdie funksie bekendgestel is, bly die RTTI-adres en lede met herwonne tipes null as jy `-y` weglaat.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver ondersteun PE-, ELF- en Mach-O-monsters vir x86, AMD64, ARM en ARM64, dus geld dieselfde werksvloei vir Go-binaries van Windows, Linux en macOS.<sup>[[10]](#references)</sup>

## Gekompileerde Python

Op hierdie bladsy kan jy uitvind hoe om die Python-kode uit ’n ELF/EXE-Python-binary te kry:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

As jy die **binary** van ’n GBA-speletjie kry, kan jy verskillende tools gebruik om dit te **emuleer** en te **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Laai die debug-weergawe af_) - Bevat ’n debugger met ’n koppelvlak
- [**mgba** ](https://mgba.io)- Bevat ’n CLI-debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), onder _**Options --> Emulation Setup --> Controls**_** ** kan jy sien hoe om die Game Boy Advance-**knoppies** te druk

![no$gba-kontrolekonfigurasie wat die Game Boy Advance-knoppietoewysings wys](<../../images/image (581).png>)

Wanneer dit gedruk word, het elke **sleutel ’n waarde** om dit te identifiseer:

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

Dus, in hierdie soort program sal die interessante deel **wees hoe die program die gebruikersinvoer hanteer**. By adres **0x4000130** vind jy die algemeen voorkomende funksie: **KEYINPUT**.

![Ghidra-aansig van ’n GBA-binêre lêer wat na KEYINPUT by adres 0x4000130 verwys](<../../images/image (447).png>)

In die vorige beeld kan jy sien dat die funksie vanaf **FUN_080015a8** (adresse: _0x080015fa_ en _0x080017ac_) opgeroep word.

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

Dit het hierdie kode gevind:

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

Die laaste if kontroleer of **`uVar4`** in die **laaste Keys** voorkom en nie die huidige sleutel is nie; dit beteken ook dat ’n knoppie losgelaat word (die huidige sleutel word in **`uVar1`** gestoor).

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

In die vorige kode kan jy sien dat ons **uVar1** (die plek waar die **waarde van die gedrukte knoppie** gestoor word) met sekere waardes vergelyk:

- Eers word dit met die **waarde 4** (**SELECT**-knoppie) vergelyk: In die uitdaging maak hierdie knoppie die skerm skoon.
- Daarna word die waarde met **8** (die **START**-knoppie) vergelyk; in hierdie uitdaging kontroleer daardie tak of die ingevoerde kode geldig is.
  - In hierdie geval word die veranderlike **`DAT_030000d8`** met 0xf3 vergelyk, en as die waarde ooreenstem, word sekere kode uitgevoer.
- In alle ander gevalle word ’n teller (`DAT_030000d4`) nagegaan en verhoog.\
  Solank die teller minder as 8 is, word die waardes van die gedrukte knoppies by `DAT_030000d8` getel.

In hierdie uitdaging moes jy dus, met kennis van die knoppiewaardes, **’n kombinasie van minder as 8 knoppies druk waarvan die waardes saam 0xf3 oplewer.**

**Verwysing vir hierdie tutoriaal:** [geargiveerde Nostalgia-uitdagingsbeskrywing](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursusse

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binêre deobfuskasie)

## References

- [1] [Vereenvoudiging van MBA-obfuskasie met CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA-bewaarplek](https://github.com/trailofbits/CoBRA)
- [3] [Dekodering van Rust-strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA-reversing-tutoriaal (geargiveer)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Om AI-ondersteunde Reverse Engineering te verslaan, of dit ten minste te probeer](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] ['n Benadering om Control Flow Graphs te vergelyk op grond van Basic Block-ooreenstemming](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver-bewaarplek](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble-obfuskasiemeganisme](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Gebruik van Control-Flow Graph-ooreenkoms om Golang-binêres outomaties te deobfuskeer](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor-bewaarplek](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Opdaterings aan Volexity se Golang-gereedskap](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [REA-ontleding van managed code](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI- en bewysgids](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
