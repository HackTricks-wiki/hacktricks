# Reversing-gereedskap en basiese metodes

{{#include ../../banners/hacktricks-training.md}}

## ImGui-gebaseerde Reversing-gereedskap

Sagteware:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows-kernelfoutopsporing

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm-dekompileerder / Wat-samesteller

Aanlyn:

- Gebruik [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) om vanaf wasm (binêr) na wat (gewone teks) te **dekompileer**
- Gebruik [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) om vanaf wat na wasm te **kompileer**
- Jy kan ook [web-wasmdec](https://wwwg.github.io/web-wasmdec/) vir dekompilering probeer.

Sagteware:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8-gekasde bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET-dekompileerder

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is ’n dekompileerder wat verskeie formate **dekompileer en ondersoek**, waaronder **biblioteke** (.dll), **Windows-metadata-lêers** (.winmd) en **uitvoerbare lêers** (.exe). Nadat ’n assembly gedekompileer is, kan dit as ’n Visual Studio-projek (.csproj) gestoor word.

Die voordeel hiervan is dat hierdie stap tyd kan bespaar wanneer verlore bronkode vanaf ’n verouderde assembly herstel moet word. Boonop maak dotPeek dit maklik om deur die gedekompileerde kode te navigeer, wat dit een van die ideale hulpmiddels vir **Xamarin-algoritme-ontleding** maak.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Met ’n omvattende add-in-model en ’n API wat die hulpmiddel uitbrei om aan jou presiese behoeftes te voldoen, bespaar .NET Reflector tyd en vereenvoudig dit ontwikkeling. Kom ons kyk na die groot verskeidenheid reverse-engineering-dienste wat hierdie hulpmiddel bied:

- Gee insig in hoe data deur ’n biblioteek of komponent vloei
- Gee insig in die implementering en gebruik van .NET-tale en -raamwerke
- Vind ongedokumenteerde en nie-blootgestelde funksionaliteit om meer uit die gebruikte API’s en tegnologieë te haal.
- Vind afhanklikhede en verskillende assemblies
- Vind die presiese ligging van foute in jou kode, derdeparty-komponente en biblioteke.
- Debug in die bronkode van al die .NET-kode waarmee jy werk.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-inprop vir Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Jy kan dit op enige bedryfstelsel gebruik (jy kan dit direk vanaf VSCode installeer; jy hoef nie die git af te laai nie. Klik op **Extensions** en **soek na ILSpy**).\
As jy weer wil **dekompileer**, **wysig** en **herkompileer**, kan jy [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) of ’n aktief onderhoude fork daarvan, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), gebruik. (**Regskliek -> Modify Method** om iets binne ’n funksie te verander).

### DNSpy-logging

Om **DNSpy sekere inligting na ’n lêer te laat log**, kan jy hierdie brokkie gebruik:

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

Dit is nodig, want as jy dit nie doen nie, sal verskeie **optimisations** tydens **runtime** op die kode toegepas word. Dit kan veroorsaak dat ’n **break-point** nooit getref word wanneer jy debug nie, of dat sommige **variables** nie bestaan nie.

As jou .NET-toepassing deur **IIS** **run** word, kan jy dit dan **restart** met:

```
iisreset /noforce
```

Dan, om te begin ontfout, moet jy alle oop lêers sluit en in die **Debug Tab** **Attach to Process...** kies:

![DNSpy Logging - DNSpy Debugging: Dan, om te begin ontfout, moet jy alle oop lêers sluit en in die Debug Tab Attach to Process kies](<../../images/image (318).png>)

Kies dan **w3wp.exe** om aan die **IIS server** te koppel en klik **attach**:

![DNSpy Logging - DNSpy Debugging: Kies dan w3wp.exe om aan die IIS server te koppel en klik attach](<../../images/image (113).png>)

Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers op _Debug >> Break All_ en klik dan op _**Debug >> Windows >> Modules**_:

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
- Kies die **Windbg**-debugger
- Kies "**Suspend on library load/unload**"

![Ontfouting van DLL's - Met IDA: Kies " Suspend on library load/unload "](<../../images/image (868).png>)

- Stel die **parameters** van die uitvoering op deur die **pad na die DLL** en die funksie wat jy wil aanroep, in te vul:

![Ontfouting van DLL's - Met IDA: Stel die parameters van die uitvoering op deur die pad na die DLL en die funksie wat jy wil aanroep, in te vul](<../../images/image (704).png>)

Wanneer jy dan begin ontfout, **sal die uitvoering stop wanneer elke DLL gelaai word**. Wanneer rundll32 jou DLL laai, sal die uitvoering dus stop.

Hierdie metode stop by modulelaaigebeurtenisse, maar om die toegangspunt van die gelaaide DLL te bereik, is minder direk as met die x64dbg-werkvloei hieronder.

### Met x64dbg/x32dbg

- **Laai rundll32** (64bits in C:\Windows\System32\rundll32.exe en 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Verander die Command Line** ( _File --> Change Command Line_ ) en stel die pad na die dll en die funksie wat jy wil aanroep, byvoorbeeld: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Verander _Options --> Settings_ en kies "**DLL Entry**".
- **Begin dan die uitvoering**; die debugger sal by elke dll main stop. Op 'n sekere punt sal jy **by die DLL Entry van jou dll stop**. Soek van daar af net die punte waar jy 'n breakpoint wil plaas.

Let daarop dat wanneer die uitvoering om enige rede in win64dbg stop, jy kan sien **in watter kode jy is** deur boaan die win64dbg-venster te kyk:

![Met IDA - Met x64dbg/x32dbg: Let daarop dat wanneer die uitvoering om enige rede in win64dbg stop, jy kan sien in watter kode jy is deur boaan die win64dbg-venster te kyk](<../../images/image (842).png>)

Hierdie aanduiding bevestig wanneer uitvoering binne die DLL wat jy wil ontfout, gestop het.

## GUI-toepassings / videospeletjies

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes binne die geheue van 'n lopende speletjie gestoor word en dit te verander. Meer inligting in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is 'n front-end-/reverse-engineering-instrument vir die GNU Project Debugger (GDB), wat op speletjies fokus. Dit kan egter vir enige reverse-engineering-verwante werk gebruik word.

[**Decompiler Explorer**](https://dogbolt.org/) is 'n web-front-end vir verskeie decompilers. Met hierdie webdiens kan jy die uitvoer van verskillende decompilers op klein uitvoerbare programme vergelyk.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### Ontfouting van shellcode met blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) ken geheue vir die **shellcode** toe, druk sy **geheueadres** uit en laat die uitvoering wag.\
Koppel 'n debugger soos IDA of x64dbg, stel 'n breakpoint by die gedrukte adres en hervat die uitvoering om die shellcode te ontfout.

Die GitHub-vrystellingsbladsy bevat zip-lêers met die saamgestelde vrystellings: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Jy kan 'n effens aangepaste weergawe van Blobrunner by die volgende skakel vind. Om dit te compile, **skep net 'n C/C++-projek in Visual Studio Code, kopieer en plak die kode en bou dit**.


{{#ref}}
blobrunner.md
{{#endref}}

### Ontfouting van shellcode met jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) is soortgelyk aan BlobRunner. Dit ken geheue vir die shellcode toe en betree 'n oneindige lus. Koppel die debugger, hervat vir **2–5 sekondes**, laat dit binne daardie lus wag en stap na die volgende aanroep wat uitvoering na die toegekende shellcode oordra.

![Debugger het in jmp2it se oneindige lus gepouseer, net voor die aanroep na die toegekende shellcode](<../../images/image (509).png>)

Jy kan 'n saamgestelde weergawe van [jmp2it op die releases-bladsy aflaai](https://github.com/adamkramer/jmp2it/releases/).

### Ontfouting van shellcode met Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is die GUI van radare. Met Cutter kan jy die shellcode emuleer en dit dinamies inspekteer.

Let daarop dat Cutter jou toelaat om "Open File" en "Open Shellcode" te kies. In my geval het dit die shellcode korrek gedecompileer toe ek dit as 'n lêer oopgemaak het, maar nie toe ek dit as shellcode oopgemaak het nie:

![Cutter wys verskillende ontledingsresultate wanneer dieselfde grepe as 'n lêer of as shellcode oopgemaak word](<../../images/image (562).png>)

Om die emulasie te laat begin op die plek wat jy wil, stel daar 'n bp in. Dit lyk of Cutter dan die emulasie outomaties daar begin:

![Stel 'n breakpoint by die verlangde shellcode-toegangspunt voordat Cutter se emulasie begin](<../../images/image (589).png>)

![Cutter se emulator het by die geselekteerde shellcode-breakpoint gepouseer](<../../images/image (387).png>)

Jy kan byvoorbeeld die stack in 'n hex dump sien:

![Bekyk die geëmuleerde shellcode-stack in Cutter se hex dump](<../../images/image (186).png>)

### Deobfuskeer van shellcode en verkryging van uitgevoerde funksies

Jy moet [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) probeer.\
Dit sal jou dinge vertel soos **watter funksies** die shellcode gebruik en of die shellcode homself in die geheue **decode**.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg beskik ook oor ’n grafiese lanseerder waar jy die gewenste opsies kan kies en die shellcode kan uitvoer

![scDbg-grafiese lanseerder om shellcode-emulasie- en tracing-opsies te kies](<../../images/image (258).png>)

Die **Create Dump**-opsie sal die finale shellcode dump as enige veranderinge dinamies aan die shellcode in die geheue aangebring word (nuttig om die gedekodeerde shellcode af te laai). Die **start offset** kan nuttig wees om die shellcode by ’n spesifieke offset te begin. Die **Debug Shell**-opsie is nuttig om die shellcode met die scDbg-terminaal te debug (maar ek vind enige van die opsies wat vroeër verduidelik is, beter hiervoor, aangesien jy Ida of x64dbg kan gebruik).

### Disassemblering met CyberChef

Laai jou shellcode-lêer as invoer op en gebruik die volgende resep om dit te disassembleer: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation-deobfussering

**Mixed Boolean-Arithmetic (MBA)**-obfuscation verberg eenvoudige uitdrukkings soos `x + y` agter formules wat rekenkundige (`+`, `-`, `*`) en bitgewys-operatore (`&`, `|`, `^`, `~`, skofte) meng. Die belangrike punt is dat hierdie identiteite gewoonlik slegs korrek is onder **modulêre rekenkunde met vaste breedte**, dus maak oordragte en oorlope saak:

```c
(x ^ y) + 2 * (x & y) == x + y
```

As jy hierdie soort uitdrukking met generiese algebraïese nutsmiddels vereenvoudig, kan jy maklik ’n verkeerde resultaat kry omdat die bitwydte-semantiek geïgnoreer is.<sup>[[1]](#references)</sup>

### Praktiese werkvloei

1. **Behou die oorspronklike bitwydte** van die geligte kode/IR/decompiler-uitvoer (`8/16/32/64` bits).
2. **Klassifiseer die uitdrukking** voordat jy dit probeer vereenvoudig:
   - **Lineêr**: geweegde somme van bitwise-atome
   - **Semilineêr**: lineêr plus konstante maskers soos `x & 0xFF`
   - **Polinoom**: produkte kom voor
   - **Gemeng**: produkte en bitwise-logika is verweef, dikwels met herhaalde subuitdrukkings
3. **Verifieer elke kandidaat-herskrywing** met ewekansige toetsing of ’n SMT-bewys. As die ekwivalensie nie bewys kan word nie, behou eerder die oorspronklike uitdrukking as om te raai.

### Omseil afgeplatte beheer vloei met ’n nou uitvoeringsnit

Dit is dikwels onnodig om die volledige beheer-vloeigrafiek te herwin. Met control-flow flattening, ondeursigtige predikate, groot dispatchers of kode met baie MBA, volg verwysings vanaf geënkripteerde blobs en uitvoerbuffers na die kleinste roetine wat hulle transformeer. Reproduseer dan slegs daardie data-vloeinitsnit, of voer dit onafhanklik uit; die dispatcher is nie deel van die vereiste oplossing as die relevante toestand direk geïnisialiseer kan word nie.<sup>[[7]](#references)</sup>

’n Praktiese werkvloei is:<sup>[[7]](#references)</sup>

1. Inventariseer uitvoerbare en data-afdelings, relokasies en kruisverwysings. Dump kandidaatabelle vanaf `.rodata` terwyl hul greeprangskikking en elementwydte behoue bly.
2. Identifiseer die laaste roetine wat die plaintext- of uitvoerbuffer skryf. Teken sy insette, verwysde tabelle, ingevoerde oproepe en vereiste globale toestand aan.
3. Lig slegs daardie bewerkings in ’n Python-model met vaste bitwydte. As die snit steeds van te veel toestand afhanklik is, roep die roetine onder Unicorn, QEMU of ’n debugger aan en haak irrelevante invoere in plaas daarvan om die hele program na te boots.
4. Bevestig dat die extractor sy uitvoer werklik uit die gegewe binêre lêer aflei: verwyder stil terugvalmeganismes, soek daarin na ingebedde antwoorde en voer dit uit teen ongeziene builds met veranderde stringe, sleutels, identifiseerders, uitlegte en obfuskasiesade.

Nuttige eerste-stap-opdragte is:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Spoor MBA-uitdrukkings op wat vermomde konstantes is

’n Skynbaar invoerafhanklike greepuitdrukking kan sy invoer heeltemal kanselleer. Nadat jy die tabelle onttrek het, evalueer die uitdrukking oor die volledige 8-bis-domein; ’n enkelvoudige uitsetstel bewys dat die greep konstant is, sonder om die omliggende toestandsmasjien te herstel.<sup>[[7]](#references)</sup>

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

Keep die finale mask, want die oorspronklike optelling het byte-wydte-oorloop. Vra vir ’n breër domein ’n SMT-solver of `f(x1) != f(x2)` bevredigbaar is vir twee simboliese invoere van dieselfde breedte: `unsat` bewys invariansie, terwyl `sat` ’n teenvoorbeeld lewer en beteken dat die invoer nie weggegooi kan word nie.<sup>[[7]](#references)</sup>

#### Herken omgewingsgebonde dekodering

Anti-analise-kontroles hoef nie te vertak of te crash nie. ’n Dekodeerder kan ’n sensorresultaat by ’n sleutelbis, ’n opaque-predicate-konstante of die toestand van ’n flattened dispatcher inmeng, normaal voortgaan en geloofwaardige maar verkeerde plaintext in ’n emulator lewer. Daarom is dit nie genoeg om slegs sigbare foutvertakkings te patch nie; volg die data-afhanklikhede vanaf omgewingsondersoeke na die dekodeerdertoestand, vergelyk dieselfde kodegedeelte op die egte toestel en emulator, en toets hoe die afdwing van elke sensorresultaat die finale buffer verander.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is ’n praktiese MBA-vereenvoudiger vir malware-analise en die reversing van beskermde binaries. Dit klassifiseer die uitdrukking en stuur dit deur gespesialiseerde pyplyne, eerder as om een generiese herskryfpas op alles toe te pas.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evalueer die uitdrukking op Boolean-insette, lei ’n signature af en laat verskeie herstelmetodes teen mekaar meeding, soos patroonpassing, ANF-omskakeling en koëffisiëntinterpolasie.
- **Semilinear MBA**: atome met konstante maskers word met bit-gepartisioneerde rekonstruksie herbou sodat gemaskerde streke korrek bly.
- **Polynomial/Mixed MBA**: produkte word in kerne opgebreek, en herhaalde subuitdrukkings kan in tydelike veranderlikes opgelig word voordat die buitenste relasie vereenvoudig word.

Voorbeeld van ’n gemengde identiteit wat dikwels die moeite werd is om te probeer herwin:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dit kan vereenvoudig word tot:

```c
x * y
```

### Reversing-notas

- Verkies om CoBRA op **geligde IR-uitdrukkings** of decompiler-afvoer te laat loop nadat jy die presiese berekening geïsoleer het.
- Gebruik `--bitwidth` uitdruklik wanneer die uitdrukking van gemaskerde rekenkundige bewerkings of smal registers afkomstig is.
- As jy ’n sterker bewysstap nodig het, kyk na die plaaslike Z3-notas hier:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA word ook as ’n **LLVM-pass-inprop** (`libCobraPass.so`) versprei, wat nuttig is wanneer jy MBA-swaar LLVM IR wil normaliseer voor latere ontledingspasses.
- Ongesteunde, dra-sensitiewe gemengde-domeinresidue moet beskou word as ’n aanduiding om die oorspronklike uitdrukking te behou en die dra-pad met die hand te ontleed.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Hierdie obfuscator vervang programbewerkings met `mov`-gebaseerde instruksievolgordes en gebruik sein-/uitsonderingshantering om die beheervloei te verander. Vir besonderhede:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Vir ondersteunde binaries kan [demovfuscator](https://github.com/kirschju/demovfuscator) die resultaat deobfuskeer. Dit het verskeie afhanklikhede.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

En [installeer keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

As jy ’n **CTF** speel, kan hierdie oplossing om die flag te vind baie nuttig wees: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Om die **entry point** te vind, soek in die funksies na `::main`, soos in:

![Vind ’n Rust entry point in Ghidra deur funksiename vir double-colon main te soek](<../../images/image (1080).png>)

In hierdie geval is die binary authenticator genoem, so dit is redelik duidelik dat dit die interessante main-funksie is.\
As jy die **name** van die aangeroepte **funksies** het, soek daarna op die **Internet** om meer oor hul **insette** en **uitsette** te wete te kom.

### Herstel van Rust-stringe uit ELF-firmware

In **Rust ELF**-binaries word baie statiese stringe nie as C-styl NUL-terminated pointers verwys nie. ’n Algemene `rustc`-uitleg is ’n **pointer/lengte-tuple** binne **`.data.rel.ro`** wat na die werklike stringblob wys wat in **`.rodata`** gestoor is:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Dit beteken dat `strings` of Ghidra se verstekontleding aangrensende stringe kan saamsmelt of kruisverwysings heeltemal kan mis.<sup>[[3]](#references)</sup>

Vinnige werkvloei:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Kry die virtuele adres en grootte van **`.rodata`**.
2. Enumereer **`.data.rel.ro`** een woord op ’n slag.
3. Beskou enige waarde binne die `.rodata`-adresreeks as ’n kandidaat-stringwyser.
4. Beskou die volgende woord as die kandidaat-lengte.
5. Pas saniteitsfilters toe (byvoorbeeld, behou lengtes tussen **4** en **100** grepe).
6. Lees presies `length` grepe uit `.rodata` in plaas daarvan om te skandeer totdat jy `0x00` kry.

Minimale ekstraktorlogika:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Dit is veral nuttig wanneer firmware reverse engineering gedoen word, omdat herwonne Rust-strings dikwels **HTTP-roetes, RPC-name, logboodskappe, assertions, lêername, konfigurasiesleutels, command handlers en auth-verwante logika** onthul.

As Ghidra daardie strings mis, laat loop ’n pasgemaakte script/plugin wat dieselfde heuristiek toepas en string-data skep by die verwysde `.rodata`-offsets. Die gepubliseerde `rust-strings`- en `RustStrings.py`-tools van Pen Test Partners is goeie verwysings om die idee aan te pas vir ander **woordgroottes, endianness en seksie-uitlegte**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Vir Delphi-gecompileerde binaries kan jy [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) gebruik.

As jy ’n Delphi-binary moet reverse engineer, stel ek voor dat jy die IDA-plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) gebruik.

Druk **Alt+F7** in IDA om ’n Python-plugin te laai, en kies dan die plugin-lêer.

Hierdie plugin sal die binary uitvoer en funksiename dinamies oplos wanneer debugging begin. Nadat debugging begin het, druk weer die Start-knoppie (die groen een of f9), en ’n breakpoint sal aan die begin van die werklike kode tref.

As jy ’n knoppie in die grafiese toepassing druk, kan die debugger stop in die funksie wat deur daardie knoppie aangeroep word.

## Golang

As jy ’n Golang-binary moet reverse engineer, stel ek voor dat jy die IDA-plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) gebruik.

Druk **Alt+F7** in IDA om ’n Python-plugin te laai, en kies dan die plugin-lêer.

Dit sal die name van die funksies oplos.

## Gecompileerde Python

Op hierdie bladsy kan jy sien hoe om die Python-kode uit ’n gecompileerde ELF/EXE-Python-binary te kry:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

As jy die **binary** van ’n GBA-speletjie kry, kan jy verskillende tools gebruik om dit te **emuleer** en **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Laai die debug-weergawe af_) - Bevat ’n debugger met ’n koppelvlak
- [**mgba** ](https://mgba.io)- Bevat ’n CLI-debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), onder _**Options --> Emulation Setup --> Controls**_** ** kan jy sien hoe om die Game Boy Advance-**knoppies** te druk.

![no$gba se knoppiekonfigurasie, wat die Game Boy Advance-knoppietoewysings wys](<../../images/image (581).png>)

Wanneer dit gedruk word, het elke **knoppie ’n waarde** waarmee dit geïdentifiseer kan word:

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

Dus, in hierdie soort program sal die interessante deel wees **hoe die program die gebruiker-invoer hanteer**. By die adres **0x4000130** sal jy die algemeen voorkomende funksie vind: **KEYINPUT**.

![Ghidra-aansig van ’n GBA-binêre lêer wat na KEYINPUT by adres 0x4000130 verwys](<../../images/image (447).png>)

In die vorige prent kan jy sien dat die funksie vanaf **FUN_080015a8** (adresse: _0x080015fa_ en _0x080017ac_) opgeroep word.

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

Die laaste if kontroleer of **uVar4** in die **laaste sleutels** is en nie die huidige sleutel is nie; dit beteken ook dat ’n knoppie losgelaat word (die huidige sleutel word in **uVar1** gestoor).

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

In die vorige kode kan jy sien dat ons **uVar1** (die plek waar die **waarde van die gedrukte knoppie** is) met sekere waardes vergelyk:

- Eerstens word dit met die **waarde 4** (**SELECT**-knoppie) vergelyk: In die uitdaging maak hierdie knoppie die skerm skoon.
- Daarna word die waarde met **8** (die **START**-knoppie) vergelyk; in hierdie uitdaging kontroleer daardie pad of die ingevoerde kode geldig is.
  - In hierdie geval word die var **`DAT_030000d8`** met 0xf3 vergelyk, en as die waarde ooreenstem, word sekere kode uitgevoer.
- In alle ander gevalle word ’n teller (`DAT_030000d4`) nagegaan en verhoog.\
  Solank die teller onder 8 is, word die waardes van die gedrukte knoppies by `DAT_030000d8` opgetel.

Dus moes jy in hierdie uitdaging, nadat jy die waardes van die knoppies geken het, **’n kombinasie met ’n lengte kleiner as 8 druk waarvan die som 0xf3 is.**

**Verwysing vir hierdie tutoriaal:** [geargiveerde Nostalgia-uitdagingskrywe](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [3] [Dekodering van Rust-stringe - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reverse-engineering-tutoriaal (geargiveer)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Die oorwinning van KI-ondersteunde reverse engineering, of ten minste ’n poging daartoe](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
