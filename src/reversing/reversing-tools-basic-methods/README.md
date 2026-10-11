# Reversing-nutsgoed en basiese metodes

{{#include ../../banners/hacktricks-training.md}}

## ImGui-gebaseerde reversing-nutsgoed

Sagteware:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows-kernontfouting

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm-decompiler / Wat-compiler

Aanlyn:

- Gebruik [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) om van wasm (binêr) na wat (gewone teks) te **decompile**
- Gebruik [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) om van wat na wasm te **compile**
- Jy kan ook [web-wasmdec](https://wwwwg.github.io/web-wasmdec/) vir decompilation probeer.

Sagteware:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8-gekasheerde bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET-decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is ’n decompiler wat verskeie formate **decompile en ondersoek**, insluitend **biblioteke** (.dll), **Windows-metadata-lêers** (.winmd) en **uitvoerbare lêers** (.exe). Ná decompilation kan ’n assembly as ’n Visual Studio-projek (.csproj) gestoor word.

Die voordeel is dat hierdie aksie tyd kan bespaar wanneer verlore bronkode uit ’n verouderde assembly herstel moet word. Boonop bied dotPeek handige navigasie deur die gedecompileerde kode, wat dit een van die ideale nutsgoed vir **Xamarin-algoritme-analise** maak.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Met ’n omvattende add-in-model en ’n API wat die nutsding uitbrei om aan jou presiese behoeftes te voldoen, bespaar .NET Reflector tyd en vereenvoudig dit ontwikkeling. Kom ons kyk na die talle reverse engineering-dienste wat hierdie nutsding bied:

- Bied insig in hoe data deur ’n biblioteek of komponent vloei
- Bied insig in die implementering en gebruik van .NET-tale en -raamwerke
- Vind ongedokumenteerde en nie-blootgestelde funksionaliteit om meer uit die API’s en tegnologieë wat gebruik word, te haal.
- Vind afhanklikhede en verskillende assemblies
- Vind die presiese ligging van foute in jou kode, derdeparty-komponente en biblioteke.
- Ontfout die bronkode van al die .NET-kode waarmee jy werk.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-inprop vir Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Jy kan dit op enige bedryfstelsel gebruik (jy kan dit direk vanaf VSCode installeer; jy hoef nie die git af te laai nie. Klik op **Extensions** en **soek na ILSpy**).\
As jy weer wil **decompile**, **modify** en **recompile**, kan jy [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) of ’n aktief onderhoude fork daarvan, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), gebruik. (**Regsklik -> Modify Method** om iets binne ’n funksie te verander).

### DNSpy-logging

Om **DNSpy sekere inligting na ’n lêer te laat log**, kan jy hierdie brokkie gebruik:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Om code met DNSpy te debug, moet jy:

Eerstens, verander die **Assembly attributes** wat met **debugging** verband hou:

![DNSpy Logging - DNSpy Debugging: Eerstens, verander die Assembly attributes wat met debugging verband hou](<../../images/image (973).png>)

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

Stoor dan die nuwe lêer via _**Lêer >> Stoor module...**_:

![DNSpy Logging - DNSpy Debugging: Stoor dan die nuwe lêer via Lêer Stoor module](<../../images/image (602).png>)

Dit is nodig omdat verskeie **optimaliserings** tydens **runtime** op die kode toegepas sal word as jy dit nie doen nie. Dit kan daartoe lei dat ’n **breekpunt nooit getref word nie** of dat sommige **veranderlikes nie bestaan nie** wanneer jy debug.

As jou .NET-toepassing deur **IIS** **uitgevoer** word, kan jy dit dan **herbegin** met:

```
iisreset /noforce
```

Dan moet jy, om te begin ontfout, al die oopgemaakte lêers toemaak en in die **Debug Tab** **Attach to Process...** kies:

![DNSpy Logging - DNSpy Debugging: Dan moet jy, om te begin ontfout, al die oopgemaakte lêers toemaak en in die Debug Tab Attach to Process kies](<../../images/image (318).png>)

Kies dan **w3wp.exe** om aan die **IIS server** te koppel en klik **attach**:

![DNSpy Logging - DNSpy Debugging: Kies dan w3wp.exe om aan die IIS server te koppel en klik attach](<../../images/image (113).png>)

Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers op _Debug >> Break All_ en klik dan op _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers op Debug Break All en klik dan op Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers op Debug Break All en klik dan op Debug Windows Modules](<../../images/image (834).png>)

Klik op enige module in **Modules** en kies **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Klik op enige module in Modules en kies Open All Modules](<../../images/image (922).png>)

Regsklik op enige module in **Assembly Explorer** en klik **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Regsklik op enige module in Assembly Explorer en klik Sort Assemblies](<../../images/image (339).png>)

## Java-dekompileerder

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL's ontfout

### IDA gebruik

- **Laai rundll32** (64-bis in C:\Windows\System32\rundll32.exe en 32-bis in C:\Windows\SysWOW64\rundll32.exe)
- Kies die **Windbg**-ontfouter
- Kies "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Kies " Suspend on library load/unload "](<../../images/image (868).png>)

- Stel die **parameters** vir die uitvoering op deur die **pad na die DLL** en die funksie wat jy wil oproep, in te vul:

![Debugging DLLs - Using IDA: Stel die parameters vir die uitvoering op deur die pad na die DLL en die funksie wat jy wil oproep, in te vul](<../../images/image (704).png>)

Wanneer jy dan begin ontfout, **sal die uitvoering stop wanneer elke DLL gelaai word**. Die uitvoering sal dus stop wanneer rundll32 jou DLL laai.

Hierdie metode stop by module-laaigebeurtenisse, maar om die gelaaide DLL se toegangspunt te bereik, is minder eenvoudig as met die x64dbg-werkvloei hieronder.

### x64dbg/x32dbg gebruik

- **Laai rundll32** (64-bis in C:\Windows\System32\rundll32.exe en 32-bis in C:\Windows\SysWOW64\rundll32.exe)
- **Verander die Command Line** (_File --> Change Command Line_) en stel die pad na die dll en die funksie wat jy wil oproep, byvoorbeeld: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Verander _Options --> Settings_ en kies "**DLL Entry**".
- **Begin dan die uitvoering**. Die ontfouter sal by elke dll main stop; op 'n stadium sal jy **by jou dll se Entry stop**. Soek van daar af die plekke waar jy 'n breakpoint wil plaas.

Let daarop dat wanneer die uitvoering om enige rede in win64dbg stop, jy kan sien **in watter kode jy is** deur na die **bokant van die win64dbg-venster** te kyk:

![Using IDA - Using x64dbg/x32dbg: Let daarop dat wanneer die uitvoering om enige rede in win64dbg stop, jy kan sien in watter kode jy is deur na die bokant van die win64dbg-venster te kyk](<../../images/image (842).png>)

Hierdie aanwyser bevestig wanneer die uitvoering binne die DLL is wat jy wil ontfout.

## GUI-toepassings / videospeletjies

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes in die geheue van 'n speletjie wat loop, gestoor word, en om hulle te verander. Meer inligting by:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is 'n front-end-/reverse-engineering-hulpmiddel vir die GNU Project Debugger (GDB), wat op speletjies fokus. Dit kan egter vir enige reverse-engineering-verwante werk gebruik word.

[**Decompiler Explorer**](https://dogbolt.org/) is 'n web-front-end vir verskeie dekompileerders. Met hierdie webdiens kan jy die uitvoer van verskillende dekompileerders op klein uitvoerbare lêers vergelyk.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Shellcode met blobrunner ontfout

[**BlobRunner**](https://github.com/OALabs/BlobRunner) ken geheue vir die **shellcode** toe, druk sy **geheueadres** uit en laat die uitvoering wag.\
Koppel 'n ontfouter soos IDA of x64dbg, stel 'n breakpoint by die uitgedrukte adres en hervat die uitvoering om die shellcode te ontfout.

Die GitHub-vrystellingsbladsy bevat zip-lêers met die saamgestelde vrystellings: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Jy kan 'n effens gewysigde weergawe van Blobrunner by die volgende skakel vind. Om dit saam te stel, **skep eenvoudig 'n C/C++-projek in Visual Studio Code, kopieer en plak die kode en bou dit**.


{{#ref}}
blobrunner.md
{{#endref}}

### Shellcode met jmp2it ontfout

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) is soortgelyk aan BlobRunner. Dit ken geheue vir die shellcode toe en betree 'n oneindige lus. Koppel die ontfouter, hervat vir **2–5 sekondes**, laat dit binne daardie lus wag en stap na die volgende oproep wat die uitvoering na die toegekende shellcode oordra.

![Ontfouter gepouseer in jmp2it se oneindige lus, onmiddellik voor die oproep na die toegekende shellcode](<../../images/image (509).png>)

Jy kan 'n saamgestelde weergawe van [jmp2it op die vrystellingsbladsy aflaai](https://github.com/adamkramer/jmp2it/releases/).

### Shellcode met Cutter ontfout

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is die GUI van radare. Met Cutter kan jy die shellcode emuleer en dit dinamies ondersoek.

Let daarop dat Cutter jou toelaat om "Open File" en "Open Shellcode" te kies. In my geval is die shellcode korrek gedekompileer toe ek dit as 'n lêer oopgemaak het, maar nie toe ek dit as shellcode oopgemaak het nie:

![Cutter wys verskillende ontledingsresultate wanneer dieselfde grepe as 'n lêer of as shellcode oopgemaak word](<../../images/image (562).png>)

Om die emulasie op die gewenste plek te begin, stel 'n bp daar; Cutter sal blykbaar outomaties die emulasie daar begin:

![Stel 'n breakpoint by die gewenste shellcode-ingangspunt voordat Cutter-emulasie begin](<../../images/image (589).png>)

![Cutter-emulator gepouseer by die gekose shellcode-breakpoint](<../../images/image (387).png>)

Jy kan byvoorbeeld die stack in 'n hex dump sien:

![Bekyk die geëmuleerde shellcode-stack in Cutter se hex dump](<../../images/image (186).png>)

### Shellcode deobfuskeer en uitgevoerde funksies vind

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

scDbg kom ook met ’n grafiese lanseerder waarin jy die gewenste opsies kan kies en die shellcode kan uitvoer

![scDbg se grafiese lanseerder vir die keuse van shellcode-emulasie- en naspooropsies](<../../images/image (258).png>)

Die **Create Dump**-opsie sal die finale shellcode dump as enige veranderinge dinamies aan die shellcode in die geheue aangebring word (nuttig om die gedekodeerde shellcode af te laai). Die **start offset** kan nuttig wees om die shellcode by ’n spesifieke offset te begin. Die **Debug Shell**-opsie is nuttig om die shellcode met die scDbg-terminaal te ontfout (ek vind egter enige van die opsies wat voorheen verduidelik is beter hiervoor, aangesien jy Ida of x64dbg sal kan gebruik).

### Disassemblering met CyberChef

Laai jou shellcode-lêer as invoer op en gebruik die volgende resep om dit te disassembleer: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskasie van MBA-obfuskasie

**Mixed Boolean-Arithmetic (MBA)**-obfuskasie verberg eenvoudige uitdrukkings soos `x + y` agter formules wat rekenkundige (`+`, `-`, `*`) en bitgewys-operatore (`&`, `|`, `^`, `~`, shifts) meng. Die belangrike punt is dat hierdie identiteite gewoonlik slegs korrek is met **vastewydte-modulêre rekenkunde**, dus is carries en oorlope belangrik:

```c
(x ^ y) + 2 * (x & y) == x + y
```

As jy hierdie soort uitdrukking met generiese algebra-instrumente vereenvoudig, kan jy maklik ’n verkeerde resultaat kry omdat die biswydte-semantiek geïgnoreer is.<sup>[[1]](#references)</sup>

### Praktiese werkvloei

1. **Behou die oorspronklike biswydte** van die geligte code/IR/decompiler-uitset (`8/16/32/64` bits).
2. **Klassifiseer die uitdrukking** voordat jy dit probeer vereenvoudig:
   - **Lineêr**: geweegde somme van bitwise-atome
   - **Semilineêr**: lineêr plus konstante maskers soos `x & 0xFF`
   - **Polinoom**: produkte kom voor
   - **Gemeng**: produkte en bitwise-logika is verweef, dikwels met herhaalde subuitdrukkings
3. **Verifieer elke kandidaat-herskrywing** met ewekansige toetsing of ’n SMT-bewys. As die ekwivalensie nie bewys kan word nie, behou eerder die oorspronklike uitdrukking as om te raai.

### Omseil gevlakte control flow met ’n nou uitvoeringsnit

Dit is dikwels onnodig om die volledige control-flow-grafiek te herwin. Met control-flow flattening, ondeursigtige predikate, groot dispatchers of kode met baie MBA, volg verwysings vanaf geënkripteerde blobs en uitvoerbuffers na die kleinste roetine wat dit transformeer. Reproduseer dan slegs daardie data-flow-snit, of voer dit onafhanklik uit; die dispatcher is nie deel van die vereiste oplossing as die relevante toestand direk geïnisialiseer kan word nie.<sup>[[7]](#references)</sup>

’n Praktiese werkvloei is:<sup>[[7]](#references)</sup>

1. Inventariseer uitvoerbare en data-afdelings, relocations en kruisverwysings. Dump kandidaat-tabelle uit `.rodata` terwyl hul byte-volgorde en elementwydte behoue bly.
2. Identifiseer die laaste roetine wat die plaintext- of uitvoerbuffer skryf. Teken sy invoere, verwysde tabelle, geïmporteerde oproepe en vereiste globale toestand aan.
3. Lig slegs daardie bewerkings in ’n Python-model met vaste wydte. As die snit steeds van te veel toestand afhanklik is, roep die roetine onder Unicorn, QEMU of ’n debugger aan en hook irrelevante imports eerder as om die hele program na te boots.
4. Bevestig dat die extractor sy uitvoer werklik uit die verskafde binary aflei: verwyder stil terugvalopsies, soek daarin na ingebedde antwoorde en toets dit teen ongeziene builds met veranderde strings, sleutels, identifiseerders, uitlegte en obfuscation-sade.

Nuttige eerste-rondte-opdragte is:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Bespeur MBA-uitdrukkings wat vermomde konstantes is

’n Skynbaar invoerafhanklike byte-uitdrukking kan sy invoer heeltemal kanselleer. Nadat jy die tabelle daarvan onttrek het, evalueer die uitdrukking oor die volledige 8-bis-domein; ’n singleton-uitsetversameling bewys dat daardie byte konstant is, sonder dat jy die omliggende toestandsmasjien hoef te herwin.<sup>[[7]](#references)</sup>

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

Behou die finale masker omdat die oorspronklike optelling byte-wydte-omwikkeling het. Vra vir ’n wyer domein ’n SMT-solver of `f(x1) != f(x2)` bevredigbaar is vir twee simboliese insette met dieselfde wydte: `unsat` bewys invariansie, terwyl `sat` ’n teenvoorbeeld lewer en beteken dat die inset nie weggegooi kan word nie.<sup>[[7]](#references)</sup>

#### Herken omgewingsgebonde dekodering

Anti-analise-kontroles hoef nie te vertak of te crash nie. ’n Dekodeerder kan ’n sensorresultaat by ’n sleutelbis, ’n opaque-predicate-konstante of die toestand van ’n flattened-dispatcher inmeng, normaal voortgaan en geloofwaardige maar verkeerde plaintext in ’n emulator lewer. Om dus net sigbare foutvertakkings te patch, is onvoldoende; volg die data-afhanklikhede van omgewingsondersoeke na die dekodeerdertoestand, vergelyk dieselfde gedeelte op die egte toestel en die emulator, en toets hoe die afdwing van elke sensorresultaat die finale buffer verander.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is ’n praktiese MBA-vereenvoudiger vir malware-ontleding en die reverse engineering van beskermde binaries. Dit klassifiseer die uitdrukking en stuur dit deur gespesialiseerde pyplyne, eerder as om een generiese herskryfpas op alles toe te pas.<sup>[[2]](#references)</sup>

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
- **Semilinear MBA**: konstant-gemaskerde atome word met bit-gepartisioneerde rekonstruksie herbou, sodat gemaskerde streke korrek bly.
- **Polynomial/Mixed MBA**: produkte word in kerne opgebreek, en herhaalde subuitdrukkings kan in tydelike veranderlikes gelig word voordat die buitenste relasie vereenvoudig word.

Voorbeeld van ’n gemengde identiteit wat dikwels die moeite werd is om te probeer herwin:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dit kan vereenvoudig word tot:

```c
x * y
```

### Reversing-notas

- Verkies om CoBRA op **geligte IR-uitdrukkings** of decompiler-uitset te laat loop nadat jy die presiese berekening geïsoleer het.
- Gebruik `--bitwidth` eksplisiet wanneer die uitdrukking van gemaskerde rekenkundige bewerkings of smal registers afkomstig is.
- As jy ’n sterker bewysstap nodig het, kyk na die plaaslike Z3-notas hier:

{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA is ook beskikbaar as ’n **LLVM-pass-inprop** (`libCobraPass.so`), wat nuttig is wanneer jy MBA-swaar LLVM IR wil normaliseer voor latere ontledingspasses.
- Onondersteunde carry-sensitiewe gemengde-domeinresiduele moet beskou word as ’n aanduiding om die oorspronklike uitdrukking te behou en die carry-pad met die hand te ontleed.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Hierdie obfuscator vervang programbewerkings met `mov`-gebaseerde instruksiereekse en gebruik sein-/uitsonderingshantering om die beheervloei te verander. Vir meer besonderhede:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Vir ondersteunde binaries kan [demovfuscator](https://github.com/kirschju/demovfuscator) die resultaat deobfuscate. Dit het verskeie afhanklikhede.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

En [installeer keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

As jy aan ’n **CTF deelneem, kan hierdie ompad om die flag te vind** baie nuttig wees: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Om die **ingangspunt** te vind, soek in die funksies na `::main`, soos in:

![Vind ’n Rust-ingangspunt in Ghidra deur na funksiename met dubbelpunt-dubbelpunt main te soek](<../../images/image (1080).png>)

In hierdie geval is die binêre lêer authenticator genoem, so dit is redelik duidelik dat dit die interessante hooffunksie is.\
Met die **name** van die **funksies** wat opgeroep word, soek daarna op die **Internet** om meer oor hul **insette** en **uitsette** uit te vind.

### Herstel van Rust-stringe uit ELF-firmware

In **Rust ELF**-binêre lêers word baie statiese stringe nie as C-styl NUL-beëindigde wysers verwys nie. ’n Algemene `rustc`-uitleg is ’n **wyser-/lengte-tupel** binne **`.data.rel.ro`** wat na die werklike stringblob wys wat in **`.rodata`** gestoor is:

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
3. Behandel enige waarde binne die `.rodata`-adresreeks as ’n kandidaat-stringwyser.
4. Behandel die volgende woord as die kandidaat-lengte.
5. Pas gesonde-verstand-filters toe (hou byvoorbeeld lengtes tussen **4** en **100** grepe).
6. Lees presies `length` grepe uit `.rodata` in plaas daarvan om te skandeer totdat jy `0x00` teëkom.

Minimale onttrekkingslogika:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Dit is veral nuttig vir firmware-reversing, omdat herwonne Rust-strings dikwels **HTTP-roetes, RPC-name, logboodskappe, assertions, lêername, config-sleutels, command handlers en auth-verwante logika** onthul.

As Ghidra daardie strings mis, voer ’n pasgemaakte script/plugin uit wat dieselfde heuristiek toepas en string-data skep by die verwysde `.rodata`-offsets. Die gepubliseerde `rust-strings`- en `RustStrings.py`-nutsgoed van Pen Test Partners is goeie verwysings om die idee aan te pas vir ander **woordgroottes, endianness en section layouts**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Vir Delphi-gecompileerde binaries kan jy [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) gebruik.

As jy ’n Delphi-binary moet reverse, sal ek voorstel dat jy die IDA-plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) gebruik.

Druk **Alt+F7** in IDA om ’n Python-plugin te laai en kies dan die plugin-lêer.

Hierdie plugin voer die binary uit en los funksiename dinamies op wanneer debugging begin. Nadat debugging begin het, druk weer die Start-knoppie (die groen een of f9), en ’n breakpoint sal aan die begin van die werklike code tref.

As jy ’n knoppie in die grafiese toepassing druk, kan die debugger by die funksie stop wat deur daardie knoppie aangeroep word.

## Golang

Vir gewone Go-binaries kan [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) runtime-strukture herwin en funksiename in IDA verbeter. Laai die Python-plugin met **Alt+F7**.

### Herwin metadata sonder die symbol table

’n Gestroopte Go-uitvoerbare lêer benodig steeds runtime-metadata om programtellers aan funksies te koppel. [GoReSym](https://github.com/mandiant/GoReSym) vind en ontleed strukture soos `pclntab` en `moduledata` met behulp van code wat van die Go-runtime afgelei is. Dit kan funksiegrense, name, bronpaaie, tipes en boubesonderhede herwin sonder om op die konvensionele symbol table staat te maak.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

’n Obfuscator kan daardie strukture bruikbaar laat terwyl dit die herstelde name vervang. Garble hash byvoorbeeld identifiseerders en pakketpaaie en verwyder bou-, module- en ontfoutingsinligting.<sup>[[12]](#references)</sup> Die geobfuskeerde pakketbewys moet konsekwent bly vir funksies uit daardie pakket. Groepeer funksies volgens die herhaalde bewys, lei een pakket af uit sy callees, stringe en API’s, en versprei dan daardie pakketetiket na die hele groep.<sup>[[13]](#references)</sup>

### Herstel Garble-name met GoResolver

[GoResolver](https://github.com/volexity/GoResolver) kombineer runtime-simboolonttrekking met die generering van skoon verwysings en control-flow-graph- (CFG-) passing. Gebruik hierdie volgorde:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifiseer die samestellerweergawe.** Probeer eers `BuildInfo` en ingebedde weergawe-stringe. As die obfuscator dit verwyder het, vergelyk gedeeltes van die gebundelde Go-runtime met weergawe-spesifieke verwysingsruntimes. In Volexity se toetse was ongeveer `2%` van die runtime genoeg om groot Go-weergawes te onderskei. Beskou dit as ’n empiriese optimalisering, nie as ’n universele drempel nie.<sup>[[13]](#references)</sup>
2. **Bou passende verwysings.** Genereer skoon binaries vir die geïdentifiseerde Go-weergawe, teikenargitektuur en waarskynlike biblioteke. Deur die toolchain te pas, verminder jy CFG-verskille wat deur die samesteller gegenereer word.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Vergelyk funksies.** GoGrapher pas funksie-CFG’s en lewer genormaliseerde tellings van `0.0` tot `1.0`. Die passing van basiese blokke berus op ’n geweegde vergelyking van soortgelyke instruksies. Passings met hoë sekerheid koppel gerandomiseerde funksies aan die skoon implementering. Swakker passings kan steeds ’n pakket of module identifiseer.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
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

Die verstekdrempel vir betekenisvolle ooreenkomste is `0.9`. Die `--extract`- en `--graph`-skakelaars kan elke stadium afsonder, terwyl die verstek albei uitvoer omdat die herwonne runtime-metadata en CFG-bewyse mekaar aanvul.<sup>[[10]](#references)</sup> CFG-tellings is heuristies: inlining, bouvlae, argitektuur en verskille in biblioteekweergawes kan die grafiekvorm verander, dus behou onopgeloste funksies eerder as om name met lae vertroue af te dwing.<sup>[[13]](#references)</sup>

## Gekompileerde Python

Op hierdie bladsy kan jy uitvind hoe om die Python-kode uit ’n ELF/EXE-Python-saamgestelde binêre lêer te kry:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

As jy die **binêre lêer** van ’n GBA-speletjie kry, kan jy verskillende nutsprogramme gebruik om dit te **emuleer** en te **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Laai die debug-weergawe af_) - Bevat ’n debugger met ’n koppelvlak
- [**mgba** ](https://mgba.io)- Bevat ’n CLI-debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-inprop
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-inprop

In [**no$gba**](https://problemkaputt.de/gba.htm), by _**Options --> Emulation Setup --> Controls**_** ** kan jy sien hoe om die Game Boy Advance-**knoppies** te druk

![no$gba-kontrolekonfigurasie wat die Game Boy Advance-knoppietoewysings wys](<../../images/image (581).png>)

Wanneer ’n **sleutel gedruk word, het dit ’n waarde** waarmee dit geïdentifiseer kan word:

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

Dus, in hierdie soort program sal die interessante deel wees **hoe die program die gebruiker se invoer hanteer**. By adres **0x4000130** vind jy die funksie wat algemeen voorkom: **KEYINPUT**.

![Ghidra-aansig van 'n GBA-binêre lêer wat na KEYINPUT by adres 0x4000130 verwys](<../../images/image (447).png>)

In die vorige prent kan jy sien dat die funksie vanuit **FUN_080015a8** (adresse: _0x080015fa_ en _0x080017ac_) geroep word.

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

Die laaste if kontroleer of **`uVar4`** in die **last Keys** is en nie die huidige sleutel is nie; dit staan ook bekend as om ’n knoppie los te laat (die huidige sleutel word in **`uVar1`** gestoor).

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

- Eerstens word dit met die **waarde 4** (**SELECT**-knoppie) vergelyk: In die uitdaging maak hierdie knoppie die skerm skoon
- Daarna word die waarde met **8** (die **START**-knoppie) vergelyk; in hierdie uitdaging kontroleer daardie pad of die ingevoerde kode geldig is.
  - In hierdie geval word die var **`DAT_030000d8`** met 0xf3 vergelyk, en as die waarde dieselfde is, word sekere kode uitgevoer.
- In alle ander gevalle word ’n teller (`DAT_030000d4`) nagegaan en verhoog.\
  Solank die teller minder as 8 is, word die gedrukte knoppiewaardes by `DAT_030000d8` opgetel.

In hierdie uitdaging moes jy dus, met kennis van die knoppiewaardes, **’n kombinasie met ’n lengte van minder as 8 druk waarvan die som 0xf3 is.**

**Verwysing vir hierdie tutoriaal:** [geargiveerde Nostalgia-uitdaagbeskrywing](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [6] [Nostalgia - GBA-reversing-tutoriaal (geargiveer)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Die oorwinning van AI-gesteunde reverse engineering, of ten minste die poging daartoe](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [’n Benadering om beheervloeigrafieke te vergelyk op grond van basiese blokpassing](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble-obfuskasiemeganisme](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Gebruik van beheervloeigrafiek-ooreenkoms om Golang-binêre lêers outomaties te deobfuskasieer](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
