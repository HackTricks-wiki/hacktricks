# Reversing Tools en Basiese Metodes

{{#include ../../banners/hacktricks-training.md}}

## ImGui-gebaseerde Reversing tools

Sagteware:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Aanlyn:

- Gebruik [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) om van wasm (binêre formaat) na wat (duidelike teks) te **decompile**
- Gebruik [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) om van wat na wasm te **compile**
- Jy kan ook [web-wasmdec](https://wwwg.github.io/web-wasmdec/) vir decompilation probeer.

Sagteware:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is 'n decompiler wat **veelvuldige formate decompile en ondersoek**, insluitend **libraries** (.dll), **Windows metadata file**s (.winmd) en **executables** (.exe). Nadat dit gedecompileer is, kan 'n assembly as 'n Visual Studio-projek (.csproj) gestoor word.

Die voordeel hiervan is dat indien verlore bronkode vanaf 'n legacy assembly herstel moet word, hierdie aksie tyd kan bespaar. Verder bied dotPeek handige navigasie deur die gedecompileerde kode, wat dit een van die perfekte tools vir **Xamarin algorithm analysis** maak.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Met 'n omvattende add-in-model en 'n API wat die tool uitbrei om by jou presiese behoeftes te pas, bespaar .NET reflector tyd en vereenvoudig dit development. Kom ons kyk na die oorvloed reverse engineering-dienste wat hierdie tool bied:

- Bied insig in hoe die data deur 'n library of component vloei
- Bied insig in die implementering en gebruik van .NET-tale en frameworks
- Vind ongedokumenteerde en onblootgestelde funksionaliteit om meer uit die gebruikte APIs en technologies te haal.
- Vind dependencies en verskillende assemblies
- Spoor die presiese ligging van errors in jou kode, third-party components en libraries op.
- Debug in die source van al die .NET-kode waarmee jy werk.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Jy kan dit op enige OS gebruik (jy kan dit direk vanaf VSCode installeer; jy hoef nie die git af te laai nie. Klik op **Extensions** en **search ILSpy**).\
As jy moet **decompile**, **modify** en weer **recompile**, kan jy [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) of 'n aktief onderhoude fork daarvan, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), gebruik. (**Right Click -> Modify Method** om iets binne 'n function te verander).

### DNSpy Logging

Om **DNSpy some information in a file te laat log**, kan jy hierdie snippet gebruik:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy-ontfouting

Om kode met DNSpy te ontfout, moet jy:

Eerstens die **Assembly attributes** wat met **ontfouting** verband hou, verander:

![DNSpy Logging - DNSpy-ontfouting: Eerstens die Assembly attributes wat met ontfouting verband hou, verander](<../../images/image (973).png>)

Vanaf:
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

Dit is nodig, want as jy dit nie doen nie, sal verskeie **optimisations** tydens **runtime** op die kode toegepas word, en dit kan gebeur dat ’n **break-point** nooit tydens debugging bereik word nie, of dat sommige **variables** nie bestaan nie.

As jou .NET-toepassing dan deur **IIS** **run** word, kan jy dit met die volgende herbegin:
```
iisreset /noforce
```
Dan, om debugging te begin, moet jy al die oopgemaakte lêers sluit en binne die **Debug Tab** **Attach to Process...** kies:

![DNSpy Logging - DNSpy Debugging: Dan, om debugging te begin, moet jy al die oopgemaakte lêers sluit en binne die Debug Tab Attach to Process kies](<../../images/image (318).png>)

Kies dan **w3wp.exe** om aan die **IIS server** te koppel en klik **attach**:

![DNSpy Logging - DNSpy Debugging: Kies dan w3wp.exe om aan die IIS server te koppel en klik attach](<../../images/image (113).png>)

Noudat ons die proses debug, is dit tyd om dit te stop en al die modules te laai. Klik eers op _Debug >> Break All_ en klik dan op _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses debug, is dit tyd om dit te stop en al die modules te laai. Klik eers op Debug Break All en klik dan op Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses debug, is dit tyd om dit te stop en al die modules te laai. Klik eers op Debug Break All en klik dan op Debug Windows Modules](<../../images/image (834).png>)

Klik enige module in **Modules** en kies **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Klik enige module in Modules en kies Open All Modules](<../../images/image (922).png>)

Regsklik enige module in **Assembly Explorer** en klik **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Regsklik enige module in Assembly Explorer en klik Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Gebruik van IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe en 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Kies die **Windbg** debugger
- Kies "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Kies " Suspend on library load/unload "](<../../images/image (868).png>)

- Stel die **parameters** van die uitvoering op deur die **path to the DLL** en die funksie wat jy wil oproep, in te voer:

![Debugging DLLs - Using IDA: Stel die parameters van die uitvoering op deur die path to the DLL en die funksie wat jy wil oproep, in te voer](<../../images/image (704).png>)

Wanneer jy dan debugging begin, **sal die uitvoering gestop word wanneer elke DLL gelaai word**, en wanneer rundll32 jou DLL laai, sal die uitvoering gestop word.

Hierdie metode stop by module-load events, maar om die entry point van die gelaaide DLL te bereik, is minder direk as met die x64dbg-workflow hieronder.

### Gebruik van x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe en 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) en stel die path van die dll en die funksie wat jy wil oproep, byvoorbeeld: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Verander _Options --> Settings_ en kies "**DLL Entry**".
- **Begin dan die uitvoering**, die debugger sal by elke dll main stop; op ’n stadium sal jy **by die dll Entry van jou dll stop**. Van daar af hoef jy slegs die punte te soek waar jy ’n breakpoint wil plaas.

Let daarop dat wanneer die uitvoering om enige rede in win64dbg gestop word, jy kan sien **in watter code jy is** deur bo-aan die win64dbg-venster te kyk:

![Using IDA - Using x64dbg/x32dbg: Let daarop dat wanneer die uitvoering om enige rede in win64dbg gestop word, jy kan sien in watter code jy is deur bo-aan die win64dbg-venster te kyk](<../../images/image (842).png>)

Hierdie indicator bevestig wanneer die uitvoering binne die DLL wat jy wil debug, gestop het.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is ’n nuttige program om te vind waar belangrike waardes binne die memory van ’n lopende game gestoor word en dit te verander. Meer inligting in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is ’n front-end/reverse engineering tool vir die GNU Project Debugger (GDB), gefokus op games. Dit kan egter vir enige reverse-engineering-verwante werk gebruik word.

[**Decompiler Explorer**](https://dogbolt.org/) is ’n web-front-end vir ’n aantal decompilers. Hierdie webdiens laat jou toe om die output van verskillende decompilers op klein executables te vergelyk.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging van ’n shellcode met blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) allokeer die **shellcode**, druk sy **memory address** uit en pouseer die uitvoering.\
Koppel ’n debugger soos IDA of x64dbg, stel ’n breakpoint by die uitgedrukte address, en hervat die uitvoering om die shellcode te debug.

Die releases github page bevat zips met die compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Jy kan ’n effens aangepaste weergawe van Blobrunner by die volgende link vind. Om dit te compile, **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging van ’n shellcode met jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) is soortgelyk aan BlobRunner. Dit allokeer die shellcode en gaan ’n oneindige loop binne. Koppel die debugger, hervat dit vir **2–5 seconds**, pouseer binne daardie loop en step na die volgende call wat die uitvoering na die geallokeerde shellcode oordra.

![Debugger paused in jmp2it's infinite loop immediately before the call to the allocated shellcode](<../../images/image (509).png>)

Jy kan ’n compiled weergawe van [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/) aflaai.

### Debugging van shellcode met Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is die GUI van radare. Met Cutter kan jy die shellcode emulateer en dit dinamies inspekteer.

Let daarop dat Cutter jou toelaat om "Open File" en "Open Shellcode" te kies. In my geval, toe ek die shellcode as ’n file oopgemaak het, het dit dit korrek gedecompileer, maar toe ek dit as ’n shellcode oopgemaak het, het dit nie:

![Cutter showing different analysis results when opening the same bytes as a file or as shellcode](<../../images/image (562).png>)

Om die emulation te begin op die plek waar jy wil, stel ’n bp daar en Cutter sal blykbaar outomaties die emulation van daar af begin:

![Setting a breakpoint at the desired shellcode entry before starting Cutter emulation](<../../images/image (589).png>)

![Cutter emulator paused at the selected shellcode breakpoint](<../../images/image (387).png>)

Jy kan byvoorbeeld die stack binne ’n hex dump sien:

![Viewing the emulated shellcode stack in Cutter's hex dump](<../../images/image (186).png>)

### Deobfuscating van shellcode en verkryging van uitgevoerde funksies

Jy behoort [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) te probeer.\
Dit sal jou dinge vertel soos **watter funksies** die shellcode gebruik en of die shellcode homself in memory **decode**.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg beskik ook oor ’n grafiese launcher waar jy die gewenste opsies kan kies en die shellcode kan uitvoer

![scDbg graphical launcher for selecting shellcode emulation and tracing options](<../../images/image (258).png>)

Die **Create Dump**-opsie sal die finale shellcode dump as enige verandering dinamies aan die shellcode in die geheue aangebring word (nuttig om die gedekodeerde shellcode af te laai). Die **start offset** kan nuttig wees om die shellcode by ’n spesifieke offset te begin. Die **Debug Shell**-opsie is nuttig om die shellcode met die scDbg-terminal te debug (ek vind egter enige van die opsies wat vroeër verduidelik is beter hiervoor, aangesien jy Ida of x64dbg sal kan gebruik).

### Disassembling using CyberChef

Laai jou shellcode-lêer as invoer op en gebruik die volgende resep om dit te decompileer: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)**-obfuscation verberg eenvoudige uitdrukkings soos `x + y` agter formules wat rekenkundige (`+`, `-`, `*`) en bitwise-operatore (`&`, `|`, `^`, `~`, shifts) kombineer. Die belangrike deel is dat hierdie identiteite gewoonlik slegs korrek is onder **vaste-breedte modulêre rekenkunde**, dus maak carries en overflows saak:
```c
(x ^ y) + 2 * (x & y) == x + y
```
As jy hierdie soort uitdrukking met generiese algebraïese tooling vereenvoudig, kan jy maklik ’n verkeerde resultaat kry omdat die bit-width-semantiek geïgnoreer is.<sup>[[1]](#references)</sup>

### Praktiese workflow

1. **Behou die oorspronklike bit-width** van die geligte kode/IR/decompiler-uitset (`8/16/32/64` bits).
2. **Klassifiseer die uitdrukking** voordat jy dit probeer vereenvoudig:
- **Lineêr**: geweegde somme van bitwise atoms
- **Semilineêr**: lineêr plus konstante masks soos `x & 0xFF`
- **Polinoom**: produkte kom voor
- **Gemeng**: produkte en bitwise-logika is vervleg, dikwels met herhaalde subuitdrukkings
3. **Verifieer elke kandidaat-herskrywing** met random testing of ’n SMT proof. As die ekwivalensie nie bewys kan word nie, behou die oorspronklike uitdrukking eerder as om te raai.

### Omseil flattened control flow met ’n nou execution slice

Om die volledige control-flow graph te herstel, is dikwels onnodig. Met Control-flow flattening, opaque predicates, groot dispatchers of MBA-heavy code, volg verwysings vanaf encrypted blobs en output buffers na die kleinste routine wat dit transformeer. Reproduseer dan net daardie data-flow slice, of voer dit onafhanklik uit; die dispatcher is nie deel van die vereiste oplossing nie as die relevante state direk geïnisialiseer kan word.<sup>[[7]](#references)</sup>

’n Praktiese workflow is:<sup>[[7]](#references)</sup>

1. Maak ’n inventaris van executable- en data-sections, relocations en cross-references. Dump kandidaat-tabelle uit `.rodata` terwyl hul byte order en element width behoue bly.
2. Identifiseer die laaste routine wat na die plaintext- of output buffer skryf. Teken sy inputs, verwysde tabelle, imported calls en vereiste global state aan.
3. Lift net daardie operasies na ’n fixed-width Python-model. As die slice steeds van te veel state afhang, invoke die routine onder Unicorn, QEMU of ’n debugger en hook irrelevante imports eerder as om die hele program te emuleer.
4. Valideer dat die extractor werklik sy output uit die verskafde binary aflei: verwyder silent fallbacks, deursoek dit vir ingebedde antwoorde en voer dit uit teen unseen builds met veranderde strings, keys, identifiers, layouts en obfuscation seeds.

Nuttige eerste-pass-opdragte is:<sup>[[7]](#references)</sup>
```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```
#### Bespeur MBA-expressies wat as konstantes vermom is

’n Oënskynlik invoerafhanklike byte-expressie kan sy invoer volledig kanselleer. Nadat jy sy tabelle onttrek het, evalueer jy die expressie oor die volledige 8-bis-domein; ’n singleton-uitsetversameling bewys dat daardie byte konstant is sonder om die omliggende toestandsmasjien te herstel.<sup>[[7]](#references)</sup>
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
Behou die finale mask omdat die oorspronklike optelling byte-width wraparound het. Vir ’n wyer domein, vra ’n SMT solver of `f(x1) != f(x2)` bevredigbaar is vir twee simboliese insette met dieselfde breedte: `unsat` bewys invariansie, terwyl `sat` ’n teenvoorbeeld verskaf en beteken dat die inset nie weggegooi kan word nie.<sup>[[7]](#references)</sup>

#### Herken omgewingsgebonde decoding

Anti-analysis-kontroles hoef nie te vertak of te crash nie. ’n Decoder kan ’n sensorresultaat in ’n sleutelbit, ’n opaque-predicate-konstante of flattened-dispatcher-toestand meng, normaal voortgaan en aanneemlike maar vals plaintext in ’n emulator produseer. Daarom is dit onvoldoende om slegs sigbare failure-vertakkings te patch; volg data-afhanklikhede vanaf omgewingsprobes na decoder-toestand, vergelyk dieselfde slice op die outentieke toestel en emulator, en toets hoe die afdwinging van elke sensorresultaat die finale buffer verander.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is ’n praktiese MBA-simplifier vir malware analysis en protected-binary reversing. Dit klassifiseer die uitdrukking en stuur dit deur gespesialiseerde pipelines in plaas daarvan om een generiese rewrite-pass op alles toe te pas.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evalueer die uitdrukking op Boolean-insette, lei ’n signature af, en laat verskeie recovery-metodes parallel meeding, soos pattern matching, ANF conversion en coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms word herbou met bit-partitioned reconstruction sodat gemaskerde streke korrek bly.
- **Polynomial/Mixed MBA**: produkte word in cores ontbind, en herhaalde subexpressions kan in temporaries opgelig word voordat die outer relation vereenvoudig word.

Voorbeeld van ’n mixed identity wat dikwels die moeite werd is om te probeer recover:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Dit kan vereenvoudig word tot:
```c
x * y
```
### Reversing-aantekeninge

- Verkies om CoBRA op **geligte IR-uitdrukkings** of decompiler-uitvoer uit te voer nadat jy die presiese berekening geïsoleer het.
- Gebruik `--bitwidth` eksplisiet wanneer die uitdrukking uit gemaskerde rekenkunde of nou registers afkomstig is.
- As jy ’n sterker bewysstap benodig, raadpleeg die plaaslike Z3-aantekeninge hier:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA word ook as ’n **LLVM pass-plugin** (`libCobraPass.so`) verskaf, wat nuttig is wanneer jy MBA-swaar LLVM IR wil normaliseer vóór verdere ontledingspasses.
- Residuele gemengde-domein-uitdrukkings met onondersteunde carry-afhanklikhede moet as ’n aanduiding behandel word om die oorspronklike uitdrukking te behou en die carry-pad handmatig te ontleed.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Hierdie obfuscator vervang programbewerkings met `mov`-gebaseerde instruksiereekse en gebruik sein-/uitsonderingshantering om die control flow te verander. Vir besonderhede:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Vir ondersteunde binaries kan [demovfuscator](https://github.com/kirschju/demovfuscator) die resultaat deobfuscate. Dit het verskeie afhanklikhede.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
En [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

As jy ’n **CTF speel, kan hierdie workaround om die flag te vind** baie nuttig wees: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Om die **entry point** te vind, soek die funksies volgens `::main`, soos in:

![Vind ’n Rust-entry point in Ghidra deur funksiename vir dubbelkolon-main te soek](<../../images/image (1080).png>)

In hierdie geval is die binary authenticator genoem, dus is dit redelik duidelik dat dit die interessante main-funksie is.\
Met die **name** van die **functions** wat geroep word, soek daarvoor op die **Internet** om meer oor hul **inputs** en **outputs** te leer.

### Herstel van Rust-strings uit ELF-firmware

In **Rust ELF**-binaries word baie statiese strings nie as C-styl NUL-terminated pointers verwys nie. ’n Algemene `rustc`-uitleg is ’n **pointer/length tuple** binne **`.data.rel.ro`** wat na die werklike string blob wys wat in **`.rodata`** gestoor word:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Dit beteken dat `strings` of Ghidra se verstekanalise aangrensende strings kan saamsmelt of kruisverwysings heeltemal kan mis.<sup>[[3]](#references)</sup>

Vinnige workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Kry die virtuele adres en grootte van **`.rodata`**.
2. Enumereer **`.data.rel.ro`** een woord op ’n slag.
3. Behandel enige waarde binne die **`.rodata`**-adresreeks as ’n kandidaat-stringwyser.
4. Behandel die volgende woord as die kandidaat-lengte.
5. Pas redelikheidsfilters toe (byvoorbeeld, behou lengtes tussen **4** en **100** grepe).
6. Lees presies `length` grepe vanaf **`.rodata`** in plaas daarvan om te skandeer totdat `0x00` gevind word.

Minimale extractor-logika:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Dit is veral nuttig in firmware reversing omdat herwonne Rust strings dikwels **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers en auth-related logic** openbaar maak.

As Ghidra daardie strings mis, voer ’n custom script/plugin uit wat dieselfde heuristiek toepas en string data by die verwysde `.rodata` offsets skep. Die gepubliseerde `rust-strings`- en `RustStrings.py`-tools van Pen Test Partners is goeie verwysings om die idee vir ander **word sizes, endianness en section layouts** aan te pas.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Vir Delphi compiled binaries kan jy [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) gebruik.

As jy ’n Delphi binary moet reverse, stel ek voor dat jy die IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) gebruik.

Druk **Alt+F7** in IDA om ’n Python plugin te laai, en kies dan die plugin file.

Hierdie plugin sal die binary uitvoer en function names dinamies aan die begin van die debugging resolve. Nadat jy die debugging begin het, druk weer die Start-knoppie (die groen een of f9), en ’n breakpoint sal aan die begin van die werklike code tref.

As jy ’n knoppie in die graphical application druk, kan die debugger stop by die function wat deur daardie knoppie invoked word.

## Golang

As jy ’n Golang binary moet reverse, stel ek voor dat jy die IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) gebruik.

Druk **Alt+F7** in IDA om ’n Python plugin te laai, en kies dan die plugin file.

Dit sal die names van die functions resolve.

## Compiled Python

Op hierdie bladsy kan jy vind hoe om die Python code uit ’n ELF/EXE Python compiled binary te kry:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

As jy die **binary** van ’n GBA game kry, kan jy verskillende tools gebruik om dit te **emulate** en **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Laai die debug-weergawe af_) - Bevat ’n debugger met ’n interface
- [**mgba** ](https://mgba.io)- Bevat ’n CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), onder _**Options --> Emulation Setup --> Controls**_** ** kan jy sien hoe om die Game Boy Advance **buttons** te druk.

![no$gba-kontrolekonfigurasie wat Game Boy Advance-knoppie-karterings wys](<../../images/image (581).png>)

Wanneer dit gedruk word, het elke **key ’n value** om dit te identifiseer:
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
Dus, in hierdie soort program sal die interessante deel wees **hoe die program die gebruikersinvoer hanteer**. By adres **0x4000130** sal jy die algemeen voorkomende funksie: **KEYINPUT** vind.

![Ghidra-aansig van ’n GBA-binêre lêer wat na KEYINPUT by adres 0x4000130 verwys](<../../images/image (447).png>)

In die vorige afbeelding kan jy sien dat die funksie vanuit **FUN_080015a8** geroep word (adresse: _0x080015fa_ en _0x080017ac_).

In daardie funksie, ná ’n paar init-bewerkings (sonder enige belang):
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
Die volgende kode is gevind:
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
Die laaste if kontroleer of **`uVar4`** in die **laaste Keys** is en nie die huidige sleutel is nie, ook genoem om ’n knoppie te laat los (die huidige sleutel word in **`uVar1`** gestoor).
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
In die vorige code kan jy sien dat ons **uVar1** (die plek waar die **waarde van die gedrukte knoppie** is) met sommige waardes vergelyk:

- Eerstens word dit met die **waarde 4** (die **SELECT**-knoppie) vergelyk: In die challenge maak hierdie knoppie die skerm skoon
- Daarna vergelyk dit die waarde met **8** (die **START**-knoppie); in hierdie challenge kontroleer daardie pad of die ingevoerde kode geldig is.
- In hierdie geval word die var **`DAT_030000d8`** met 0xf3 vergelyk, en indien die waarde dieselfde is, word sekere code uitgevoer.
- In elke ander geval word ’n teller (`DAT_030000d4`) nagegaan en verhoog.\
Solank die teller onder 8 is, word die gedrukte-sleutelwaardes in `DAT_030000d8` opgehoop.

In hierdie challenge moes jy dus, nadat jy die waardes van die knoppies geken het, **’n kombinasie met ’n lengte kleiner as 8 druk waarvan die resulterende optelling 0xf3 is.**

**Verwysing vir hierdie tutoriaal:** [gear giveerde Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursusse

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Vereenvoudiging van MBA obfuscation met CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA-bewaarplek](https://github.com/trailofbits/CoBRA)
- [3] [Dekodering van Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing-tutoriaal (geargiveer)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI-gesteunde Reverse Engineering te verslaan, of ten minste om dit te probeer](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
