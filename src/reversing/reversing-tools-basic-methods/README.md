# Reversing Tools & Basiese Metodes

{{#include ../../banners/hacktricks-training.md}}

## ImGui-gebaseerde Reversing-tools

Sagteware:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows-kernelfoutopsporing

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm-dekompileerder / Wat-kompileerder

Aanlyn:

- Gebruik [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) om van wasm (binêr) na wat (gewone teks) te **dekompileer**
- Gebruik [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) om van wat na wasm te **kompileer**
- Jy kan ook [web-wasmdec](https://wwwg.github.io/web-wasmdec/) vir dekompilering probeer.

Sagteware:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8-gekasde bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Gevirtualiseerde payloads en pasgemaakte VMs

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET-dekompileerder

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is ’n dekompileerder wat verskeie formate **dekompileer en ondersoek**, insluitend **biblioteke** (.dll), **Windows-metadata-lêers** (.winmd) en **uitvoerbare lêers** (.exe). Nadat ’n assembly gedekompileer is, kan dit as ’n Visual Studio-projek (.csproj) gestoor word.

Die voordeel hiervan is dat hierdie aksie tyd kan bespaar wanneer verlore bronkode uit ’n verouderde assembly herstel moet word. Boonop bied dotPeek handige navigasie deur die gedekompileerde kode, wat dit een van die ideale tools vir **Xamarin-algoritme-analise** maak.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Met ’n omvattende byvoegingsmodel en ’n API wat die tool uitbrei om aan jou presiese behoeftes te voldoen, bespaar .NET Reflector tyd en vereenvoudig dit ontwikkeling. Kom ons kyk na die talle reverse engineering-dienste wat hierdie tool bied:

- Gee insig in hoe data deur ’n biblioteek of komponent vloei
- Gee insig in die implementering en gebruik van .NET-tale en -raamwerke
- Vind ongedokumenteerde en nie-blootgestelde funksionaliteit sodat jy meer uit die gebruikte APIs en tegnologieë kan haal.
- Vind afhanklikhede en verskillende assemblies
- Vind die presiese ligging van foute in jou kode, derdepartykomponente en biblioteke.
- Ontfout die bronkode van al die .NET-kode waarmee jy werk.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-inprop vir Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Jy kan dit op enige OS gebruik (jy kan dit direk vanaf VSCode installeer; jy hoef nie die git af te laai nie. Klik op **Extensions** en **soek na ILSpy**).\
As jy weer wil **dekompileer**, **wysig** en **herkompileer**, kan jy [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) of ’n aktief onderhoude fork daarvan, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), gebruik. (**Regskliek -> Modify Method** om iets binne ’n funksie te verander).

### DNSpy-logging

Om **DNSpy sekere inligting na ’n lêer te laat aanteken**, kan jy hierdie brokkie gebruik:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Om kode met DNSpy te ontfout, moet jy:

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

Dit is nodig, want as jy dit nie doen nie, sal verskeie **optimaliserings** tydens **runtime** op die kode toegepas word. Dit kan daartoe lei dat ’n **break-point nooit getref word nie** of dat sommige **veranderlikes nie bestaan nie**.

As jou .NET-toepassing dan deur **IIS** **uitgevoer** word, kan jy dit **herbegin** met:

```
iisreset /noforce
```

Dan moet jy, om met ontfouting te begin, al die oopgemaakte lêers sluit en **Attach to Process...** in die **Debug Tab** kies:

![DNSpy Logging - DNSpy Debugging: Dan moet jy, om met ontfouting te begin, al die oopgemaakte lêers sluit en Attach to Process in die Debug Tab kies](<../../images/image (318).png>)

Kies dan **w3wp.exe** om aan die **IIS server** te koppel en klik **attach**:

![DNSpy Logging - DNSpy Debugging: Kies dan w3wp.exe om aan die IIS server te koppel en klik attach](<../../images/image (113).png>)

Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers op _Debug >> Break All_ en klik dan op _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers op Debug Break All en klik dan op Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers op Debug Break All en klik dan op Debug Windows Modules](<../../images/image (834).png>)

Klik op enige module in **Modules** en kies **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Klik op enige module in Modules en kies Open All Modules](<../../images/image (922).png>)

Regskliek op enige module in **Assembly Explorer** en klik **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Regskliek op enige module in Assembly Explorer en klik Sort Assemblies](<../../images/image (339).png>)

## Java-decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs ontfout

### Met IDA

- **Laai rundll32** (64-bis in C:\Windows\System32\rundll32.exe en 32-bis in C:\Windows\SysWOW64\rundll32.exe)
- Kies die **Windbg**-ontfouter
- Kies "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Kies " Suspend on library load/unload "](<../../images/image (868).png>)

- Stel die **parameters** vir die uitvoering op deur die **pad na die DLL** en die funksie wat jy wil oproep, in te vul:

![Debugging DLLs - Using IDA: Stel die parameters vir die uitvoering op deur die pad na die DLL en die funksie wat jy wil oproep, in te vul](<../../images/image (704).png>)

Wanneer jy dan met ontfouting begin, **sal die uitvoering stop wanneer elke DLL gelaai word**. Die uitvoering sal dus stop wanneer rundll32 jou DLL laai.

Hierdie metode stop by module-laaigebeurtenisse, maar dit is minder direk om die toegangspunt van die gelaaide DLL te bereik as met die x64dbg-werkvloei hieronder.

### Met x64dbg/x32dbg

- **Laai rundll32** (64-bis in C:\Windows\System32\rundll32.exe en 32-bis in C:\Windows\SysWOW64\rundll32.exe)
- **Verander die Command Line** ( _File --> Change Command Line_ ) en stel die pad van die dll en die funksie wat jy wil oproep in, byvoorbeeld: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Verander _Options --> Settings_ en kies "**DLL Entry**".
- **Begin dan die uitvoering**. Die ontfouter sal by elke dll main stop; uiteindelik sal jy **by die DLL Entry van jou dll stop**. Soek van daar af die plekke waar jy ’n breakpoint wil plaas.

Let daarop dat wanneer die uitvoering om enige rede in win64dbg stop, jy kan sien **in watter kode jy is** deur boaan die win64dbg-venster te kyk:

![Using IDA - Using x64dbg/x32dbg: Let daarop dat wanneer die uitvoering om enige rede in win64dbg stop, jy kan sien in watter kode jy is deur boaan die win64dbg-venster te kyk](<../../images/image (842).png>)

Hierdie aanwyser bevestig wanneer die uitvoering binne die DLL wat jy wil ontfout, gestop het.

## GUI-toepassings / videospeletjies

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is ’n nuttige program om te vind waar belangrike waardes in die geheue van ’n speletjie wat loop gestoor word, en om dit te verander. Meer inligting by:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is ’n front-end-/reverse-engineering-instrument vir die GNU Project Debugger (GDB), met die fokus op speletjies. Dit kan egter vir enige reverse-engineering-verwante werk gebruik word.

[**Decompiler Explorer**](https://dogbolt.org/) is ’n web-front-end vir ’n aantal decompilers. Met hierdie webdiens kan jy die uitvoer van verskillende decompilers op klein uitvoerbare lêers vergelyk.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Ontfout ’n shellcode met blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) ken geheue toe vir die **shellcode**, druk sy **geheueadres** uit en laat die uitvoering wag.\
Koppel ’n ontfouter soos IDA of x64dbg, stel ’n breakpoint by die uitgedrukte adres en hervat die uitvoering om die shellcode te ontfout.

Die GitHub-vrystellingsbladsy bevat zip-lêers met die saamgestelde vrystellings: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Jy kan ’n effens gewysigde weergawe van Blobrunner by die volgende skakel vind. Om dit saam te stel, **skep eenvoudig ’n C/C++-projek in Visual Studio Code, kopieer en plak die kode en bou dit**.


{{#ref}}
blobrunner.md
{{#endref}}

### Ontfout ’n shellcode met jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) is soortgelyk aan BlobRunner. Dit ken geheue toe vir die shellcode en gaan ’n oneindige lus binne. Koppel die ontfouter, hervat vir **2–5 sekondes**, onderbreek binne daardie lus en stap na die volgende oproep wat uitvoering na die toegewysde shellcode oordra.

![Ontfouter onderbreek in jmp2it se oneindige lus, onmiddellik voor die oproep na die toegewysde shellcode](<../../images/image (509).png>)

Jy kan ’n saamgestelde weergawe van [jmp2it op die vrystellingsbladsy aflaai](https://github.com/adamkramer/jmp2it/releases/).

### Ontfout shellcode met Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is die GUI van radare. Met Cutter kan jy die shellcode emuleer en dit dinamies inspekteer.

Let daarop dat Cutter jou toelaat om "Open File" en "Open Shellcode" te kies. In my geval het dit die shellcode korrek gedecompileer toe ek dit as ’n lêer oopgemaak het, maar nie toe ek dit as shellcode oopgemaak het nie:

![Cutter wys verskillende ontledingsresultate wanneer dieselfde grepe as ’n lêer of as shellcode oopgemaak word](<../../images/image (562).png>)

Om die emulasie te begin by die plek wat jy wil hê, stel daar ’n bp in; Cutter sal blykbaar die emulasie outomaties van daar af begin:

![Stel ’n breakpoint by die verlangde shellcode-ingangspunt voordat Cutter se emulasie begin](<../../images/image (589).png>)

![Cutter-emulator onderbreek by die gekose shellcode-breakpoint](<../../images/image (387).png>)

Jy kan byvoorbeeld die stack in ’n heksadesimale dump sien:

![Bekyk die geëmuleerde shellcode-stack in Cutter se heksadesimale dump](<../../images/image (186).png>)

### Deobfuskeer shellcode en vind uitgevoerde funksies

Jy moet [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) probeer.\
Dit sal jou dinge vertel soos **watter funksies** die shellcode gebruik en of die shellcode homself in die geheue **dekodeer**.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg sluit ook ’n grafiese lanseerder in waar jy die gewenste opsies kan kies en die shellcode kan uitvoer

![scDbg-grafiese lanseerder om shellcode-emulasie- en nasporingsopsies te kies](<../../images/image (258).png>)

Die **Create Dump**-opsie dump die finale shellcode as enige verandering dinamies in die geheue aan die shellcode gemaak word (nuttig om die gedekodeerde shellcode af te laai). Die **start offset** kan nuttig wees om die shellcode by ’n spesifieke offset te begin. Die **Debug Shell**-opsie is nuttig om die shellcode met die scDbg-terminaal te ontfout (ek vind egter enige van die opsies wat hierbo verduidelik is beter hiervoor, aangesien jy Ida of x64dbg kan gebruik).

### Disassembleer met CyberChef

Laai jou shellcode-lêer as invoer op en gebruik die volgende resep om dit te dekompileer: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA-obfuskasie-deobfuskasie

**Mixed Boolean-Arithmetic (MBA)**-obfuskasie verberg eenvoudige uitdrukkings soos `x + y` agter formules wat rekenkundige operatore (`+`, `-`, `*`) en bisgewyse operatore (`&`, `|`, `^`, `~`, verskuiwings) kombineer. Die belangrike punt is dat hierdie identiteite gewoonlik slegs korrek is onder **vastewydte-modulêre rekenkunde**, dus maak oordragte en oorlope saak:

```c
(x ^ y) + 2 * (x & y) == x + y
```

As jy hierdie soort uitdrukking met generiese algebra-instrumentasie vereenvoudig, kan jy maklik ’n verkeerde resultaat kry omdat die biswydte-semantiek geïgnoreer is.<sup>[[1]](#references)</sup>

### Praktiese werkvloei

1. **Behou die oorspronklike biswydte** van die geligte kode/IR/decompiler-uitvoer (`8/16/32/64` bits).
2. **Klassifiseer die uitdrukking** voordat jy dit probeer vereenvoudig:
   - **Lineêr**: geweegde somme van bitwise-atome
   - **Semilineêr**: lineêr plus konstante maskers soos `x & 0xFF`
   - **Polinoom**: produkte kom voor
   - **Gemeng**: produkte en bitwise-logika is ineengevleg, dikwels met herhaalde subuitdrukkings
3. **Verifieer elke kandidaat-herskrywing** met ewekansige toetsing of ’n SMT-bewys. As die ekwivalensie nie bewys kan word nie, behou die oorspronklike uitdrukking eerder as om te raai.

### Omseil afgeplatte beheervloei met ’n nou uitvoeringsnit

Dit is dikwels onnodig om die volledige beheervloeigrafiek te herstel. Met control-flow flattening, ondeursigtige predikate, groot dispatchers of kode met baie MBA, volg verwysings vanaf geënkripteerde blobs en uitvoerb buffers na die kleinste roetine wat hulle transformeer. Reproduseer dan net daardie data-vloei-snit, of voer dit onafhanklik uit; die dispatcher is nie deel van die vereiste oplossing as die relevante toestand direk geïnisialiseer kan word nie.<sup>[[7]](#references)</sup>

’n Praktiese werkvloei is:<sup>[[7]](#references)</sup>

1. Inventariseer uitvoerbare en data-afdelings, relocations en kruisverwysings. Dump kandidaat-tabellen uit `.rodata` terwyl hulle greeprangskikking en elementwydte behoue bly.
2. Identifiseer die laaste roetine wat na die plaintext- of uitvoerbuffer skryf. Teken die invoere, verwysde tabellen, ingevoerde oproepe en vereiste globale toestand aan.
3. Lig net daardie bewerkings in ’n Python-model met vaste breedte. As die snit steeds van te veel toestand afhanklik is, roep die roetine onder Unicorn, QEMU of ’n debugger aan en hook irrelevante imports eerder as om die hele program na te boots.
4. Bevestig dat die extractor sy uitvoer werklik uit die verskafte binary aflei: verwyder stille terugvalopsies, deursoek dit vir ingebedde antwoorde en toets dit op ongeziene builds met veranderde strings, sleutels, identifiseerders, uitlegte en obfuscation seeds.

Nuttige opdragte vir ’n eerste ondersoek is:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Bespeur MBA-uitdrukkings wat as konstantes vermom is

’n Skynbaar invoerafhanklike byte-uitdrukking kan sy invoer heeltemal kanselleer. Nadat jy sy tabelle onttrek het, evalueer die uitdrukking oor die volledige 8-bis-domein; ’n uitsetversameling met net een element bewys dat daardie byte konstant is sonder om die omliggende toestandsmasjien te herwin.<sup>[[7]](#references)</sup>

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

Behou die finale maskering omdat die oorspronklike optelling omvou by die bytewydte. Vra vir ’n groter domein ’n SMT-solver of `f(x1) != f(x2)` bevredigbaar is vir twee simboliese invoere met dieselfde wydte: `unsat` bewys invariansie, terwyl `sat` ’n teenvoorbeeld oplewer en beteken dat die invoer nie weggegooi kan word nie.<sup>[[7]](#references)</sup>

#### Herken omgewingsgebonde dekodering

Anti-analise-kontroles hoef nie ’n tak te neem of te crash nie. ’n Dekodeerder kan ’n sensort resultaat in ’n sleutelbis, ’n opaque-predicate-konstante of die toestand van ’n flattened-dispatcher inmeng, normaal voortgaan en geloofwaardige maar vals plaintext in ’n emulator oplewer. Om dus slegs sigbare fouttakke te patch, is onvoldoende; volg die data-afhanklikhede vanaf omgewingsprobes na die dekodeerdertoestand, vergelyk dieselfde slice op die egte toestel en in die emulator, en toets hoe die afdwing van elke sensorresultaat die finale buffer verander.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is ’n praktiese MBA-vereenvoudiger vir malware-analise en reversing van beskermde binaries. Dit klassifiseer die uitdrukking en stuur dit deur gespesialiseerde pyplyne, eerder as om een generiese herskryfpas op alles toe te pas.<sup>[[2]](#references)</sup>

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

- **Lineêre MBA**: CoBRA evalueer die uitdrukking op Booleaanse invoere, lei ’n handtekening af en voer verskeie herstelmetodes parallel uit, soos patroonpassing, ANF-omskakeling en koëffisiëntinterpolasie.
- **Semilineêre MBA**: Atome met konstante maskering word herbou met bit-gepartisioneerde rekonstruksie, sodat gemaskerde streke korrek bly.
- **Polinoom-/Gemengde MBA**: Produkte word in kernkomponente ontbind, en herhaalde subuitdrukkings kan in tydelike veranderlikes geplaas word voordat die buitenste relasie vereenvoudig word.

Voorbeeld van ’n gemengde identiteit wat dikwels die moeite werd is om te probeer herwin:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dit kan saamgevat word as:

```c
x * y
```

### Notas oor reverse engineering

- Voer CoBRA verkieslik uit op **geligte IR-uitdrukkings** of decompiler-uitvoer nadat jy die presiese berekening geïsoleer het.
- Gebruik `--bitwidth` uitdruklik wanneer die uitdrukking afkomstig is van gemaskerde rekenkunde of smal registers.
- As jy ’n sterker bewysstap nodig het, raadpleeg die plaaslike Z3-notas hier:

{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA word ook as ’n **LLVM-pass-inprop** (`libCobraPass.so`) gelewer. Dit is nuttig wanneer jy MBA-swaar LLVM IR wil normaliseer voor latere analise-passe.
- Residuele uitdrukkings met ’n gemengde domein wat nie ondersteun word nie en sensitief is vir carry, moet beskou word as ’n teken om die oorspronklike uitdrukking te behou en die carry-pad handmatig te ontleed.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Hierdie obfuscator vervang programbewerkings met `mov`-gebaseerde instruksievolgordes en gebruik sein-/uitsonderingshantering om die beheer-vloei te verander. Vir besonderhede:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Vir ondersteunde binaries kan [demovfuscator](https://github.com/kirschju/demovfuscator) die resultaat deobfuscate. Dit het verskeie afhanklikhede.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

En [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

As jy aan ’n **CTF deelneem, kan hierdie ompad om die flag te vind** baie nuttig wees: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Om die **entry point** te vind, soek die funksies vir `::main`, soos in:

![Vind ’n Rust entry point in Ghidra deur funksiename vir dubbelkolon-main te soek](<../../images/image (1080).png>)

In hierdie geval was die binêre lêer se naam authenticator, so dit is redelik duidelik dat dit die interessante main-funksie is.\
Met die **name** van die **funksies** wat aangeroep word, soek daarna op die **Internet** om meer oor hul **insette** en **uitsette** te wete te kom.

### Herstel van Rust-strings uit ELF-firmware

In **Rust ELF**-binêre lêers word baie statiese strings nie as C-styl NUL-beëindigde pointers verwys nie. ’n Algemene `rustc`-uitleg is ’n **pointer/lengte-tuple** binne **`.data.rel.ro`** wat na die werklike stringblob wys wat in **`.rodata`** gestoor word:

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
2. Enumereer **`.data.rel.ro`** woord vir woord.
3. Behandel enige waarde binne die adresreeks van `.rodata` as ’n kandidaat-stringwyser.
4. Behandel die volgende woord as die kandidaat-lengte.
5. Pas redelikheidsfilters toe (byvoorbeeld, behou lengtes tussen **4** en **100** grepe).
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

Dit is veral nuttig vir firmware-reversing omdat herstelde Rust-strings dikwels **HTTP-roetes, RPC-name, logboodskappe, assertions, lêername, config-sleutels, command handlers en auth-verwante logika** onthul.

As Ghidra daardie strings miskyk, voer ’n pasgemaakte script/plugin uit wat dieselfde heuristiek toepas en stringdata by die verwysde `.rodata`-offsets skep. Die gepubliseerde `rust-strings`- en `RustStrings.py`-nutsgoed van Pen Test Partners is goeie verwysings om die idee by ander **woordgroottes, bytevolgordes en seksie-uitlegte** aan te pas.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Vir Delphi-saamgestelde binaries kan jy [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) gebruik.

As jy ’n Delphi-binary moet reverse, stel ek voor dat jy die IDA-plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) gebruik.

Druk **Alt+F7** in IDA om ’n Python-plugin te laai en kies dan die plugin-lêer.

Hierdie plugin voer die binary uit en bepaal funksiename dinamies wanneer debugging begin. Nadat jy debugging begin het, druk weer die Start-knoppie (die groen een of f9), en ’n breakpoint sal aan die begin van die werklike kode getref word.

As jy ’n knoppie in die grafiese toepassing druk, kan die debugger by die funksie stop wat deur daardie knoppie aangeroep word.

## Golang

Vir gewone Go-binaries kan [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) runtime-strukture herstel en funksiename in IDA verbeter. Laai die Python-plugin met **Alt+F7**.

### Herstel metadata sonder die simbooltabel

’n Gestroopte Go-uitvoerbare lêer benodig steeds runtime-metadata om programtellers aan funksies te koppel. [GoReSym](https://github.com/mandiant/GoReSym) vind en ontleed strukture soos `pclntab` en `moduledata` met behulp van kode wat uit die Go-runtime afgelei is. Dit kan funksiegrense, name, bronpaaie, tipes en bouinligting herstel sonder om op die konvensionele simbooltabel staat te maak.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

'n Obfuscator kan daardie strukture bruikbaar laat terwyl dit die herstelde name vervang. Garble has byvoorbeeld identifiseerders en pakketpaaie en verwyder bou-, module- en ontfoutinligting.<sup>[[12]](#references)</sup> Die versluierde pakkettoken moet konsekwent bly oor funksies uit daardie pakket. Groepeer funksies volgens die herhaalde token, lei een pakket uit sy callees, stringe en API's af, en ken dan daardie pakketetiket aan die hele groep toe.<sup>[[13]](#references)</sup>

### Herwin Garble-name met GoResolver

[GoResolver](https://github.com/volexity/GoResolver) kombineer onttrekking van runtimesimbole met generering van skoon verwysings en CFG-ooreenpassing (control-flow-graph). Gebruik hierdie volgorde:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifiseer die samestellerweergawe.** Probeer eers `BuildInfo` en ingebedde weergawe-stringe. As die obfuscator dit verwyder het, vergelyk gedeeltes van die gebundelde Go-runtime met weergawe-spesifieke verwysingsruntimes. In Volexity se toetse was ongeveer `2%` van die runtime genoeg om hoofweergawes van Go te onderskei. Beskou dit as 'n empiriese optimalisering, nie as 'n universele drempel nie.<sup>[[13]](#references)</sup>
2. **Bou ooreenstemmende verwysings.** Genereer skoon binaries vir die geïdentifiseerde Go-weergawe, teikenargitektuur en waarskynlike biblioteke. Deur die toolchain te pas, verminder jy CFG-verskille wat deur die samesteller gegenereer word.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Vergelyk funksies.** GoGrapher pas funksie-CFG's by mekaar en lewer genormaliseerde tellings van `0.0` tot `1.0`. Die basiese-blokpassing berus op 'n geweegde vergelyking van soortgelyke instruksies. Hoëbetroubaarheids-ooreenstemmings koppel ewekansig benoemde funksies aan die skoon implementering. Swakker ooreenstemmings kan steeds 'n pakket of module identifiseer.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Valideer en voer in.** Bevestig voorgestelde name aan die hand van oproepverhoudings, konstantes, stringe en newe-effekte, en voer dan die JSON-verslag in met die GoResolver-inprop vir IDA of Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Die verstekdrempel vir betekenisvolle passing is `0.9`. Die `--extract`- en `--graph`-skakelaars kan enige stadium afsonderlik uitvoer, terwyl die verstek albei uitvoer omdat die herwonne runtime-metadata en CFG-bewyse mekaar aanvul.<sup>[[10]](#references)</sup> CFG-tellings is heuristies: inlining, bouvlae, argitektuur en verskille in biblioteekweergawes kan die grafiekvorm verander, dus moet onopgeloste funksies behoue bly eerder as om lae-betroubaarheidsname af te dwing.<sup>[[13]](#references)</sup>

## Gekompileerde Python

Op hierdie bladsy kan jy vind hoe om die Python-kode uit ’n ELF/EXE Python-compiled binary te kry:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

As jy die **binary** van ’n GBA-speletjie kry, kan jy verskillende nutsgoed gebruik om dit te **emuleer** en te **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Laai die debug-weergawe af_) - Bevat ’n debugger met ’n koppelvlak
- [**mgba** ](https://mgba.io)- Bevat ’n CLI-debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-inprop
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-inprop

In [**no$gba**](https://problemkaputt.de/gba.htm), onder _**Options --> Emulation Setup --> Controls**_** ** kan jy sien hoe om die Game Boy Advance-**knoppies** te druk

![no$gba-beheerinstellings wat die Game Boy Advance-knoppietoewysings wys](<../../images/image (581).png>)

Wanneer ’n **sleutel** ingedruk word, het dit ’n waarde waarmee dit geïdentifiseer kan word:

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

Dus, in hierdie soort program sal die interessante deel wees **hoe die program die gebruiker se invoer hanteer**. By die adres **0x4000130** vind jy die algemeen voorkomende funksie: **KEYINPUT**.

![Ghidra-aansig van ’n GBA-binêre lêer wat na KEYINPUT by adres 0x4000130 verwys](<../../images/image (447).png>)

In die vorige beeld kan jy sien dat die funksie vanaf **FUN_080015a8** geroep word (adresse: _0x080015fa_ en _0x080017ac_).

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

Die laaste if kontroleer of **`uVar4`** in die **laaste sleutels** is en nie die huidige sleutel is nie; dit beteken ook dat 'n knoppie losgelaat word (die huidige sleutel word in **`uVar1`** gestoor).

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
- Dan word die waarde met **8** (die **START**-knoppie) vergelyk; in hierdie uitdaging kontroleer daardie pad of die ingevoerde kode geldig is.
  - In hierdie geval word die var **`DAT_030000d8`** met 0xf3 vergelyk, en as die waarde dieselfde is, word sekere kode uitgevoer.
- In alle ander gevalle word ’n teller (`DAT_030000d4`) nagegaan en verhoog.\
  Solank die teller kleiner as 8 is, word die gedrukte sleutelwaardes in `DAT_030000d8` opgetel.

In hierdie uitdaging moes jy dus, met kennis van die knoppiewaardes, **’n kombinasie met ’n lengte kleiner as 8 druk waarvan die som 0xf3 is.**

**Verwysing vir hierdie tutoriaal:** [geargiveerde Nostalgia-uitdagingsoplossing](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursusse

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binêre de-obfuskasie)

## References

- [1] [Vereenvoudiging van MBA-obfuskasie met CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA-bewaarplek](https://github.com/trailofbits/CoBRA)
- [3] [Dekodering van Rust-stringe - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA Reverse Engineering-tutoriaal (geargiveer)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Om AI-ondersteunde Reverse Engineering te verslaan, of dit ten minste te probeer](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [’n Benadering om beheervloeigrafieke te vergelyk op grond van basiese-blokpassing](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble-obfuskasiemeganisme](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Gebruik van beheervloeigrafieksimilariteit om Golang-binêre lêers outomaties te de-obfuskeer](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
