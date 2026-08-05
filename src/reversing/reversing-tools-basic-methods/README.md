# Reversing Tools & Basiese Metodes

{{#include ../../banners/hacktricks-training.md}}

## ImGui-gebaseerde Reversing tools

Sagteware:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Aanlyn:

- Gebruik [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) om van wasm (binary) na wat (duidelike teks) te **decompile**
- Gebruik [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) om van wat na wasm te **compile**
- jy kan ook probeer om [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) te gebruik om te decompile

Sagteware:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is 'n decompiler wat **verskeie formate decompileer en ondersoek**, insluitend **libraries** (.dll), **Windows metadata-lêers** (.winmd), en **executables** (.exe). Nadat dit gedecompileer is, kan 'n assembly as 'n Visual Studio-projek (.csproj) gestoor word.

Die voordeel hiervan is dat indien verlore source code vanaf 'n legacy assembly herstel moet word, hierdie aksie tyd kan bespaar. Verder bied dotPeek handige navigasie deur die gedecompileerde code, wat dit een van die perfekte tools vir **Xamarin algorithm analysis** maak.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Met 'n omvattende add-in-model en 'n API wat die tool uitbrei om aan jou presiese behoeftes te voldoen, bespaar .NET reflector tyd en vereenvoudig dit development. Kom ons kyk na die oorvloed reverse engineering-dienste wat hierdie tool bied:

- Bied insig in hoe die data deur 'n library of komponent vloei
- Bied insig in die implementering en gebruik van .NET-tale en frameworks
- Vind ongedokumenteerde en onblootgestelde funksionaliteit om meer uit die gebruikte APIs en tegnologieë te kry.
- Vind dependencies en verskillende assemblies
- Spoor die presiese ligging van foute in jou code, derdeparty-komponente en libraries op.
- Debug in die source van al die .NET-code waarmee jy werk.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Jy kan dit op enige OS gebruik (jy kan dit direk vanaf VSCode installeer; jy hoef nie die git af te laai nie. Klik op **Extensions** en **search ILSpy**).\
As jy moet **decompile**, **modify** en weer **recompile**, kan jy [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) of 'n aktief onderhoude fork daarvan, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), gebruik. (**Right Click -> Modify Method** om iets binne 'n funksie te verander).

### DNSpy Logging

Om **DNSpy sommige inligting in 'n lêer te laat log**, kan jy hierdie snippet gebruik:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Om code met DNSpy te debug, moet jy:

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Stoor dan die nuwe lêer via _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Dit is nodig omdat verskeie **optimalisasies** tydens **runtime** op die kode toegepas sal word as jy dit nie doen nie, en dit moontlik kan wees dat ’n **break-point** tydens debugging nooit bereik word nie, of dat sommige **variables** nie bestaan nie.

As jou .NET-toepassing dan deur **IIS** **run** word, kan jy dit met die volgende herbegin:
```
iisreset /noforce
```
Dan, om te begin debug, moet jy al die oopgemaakte lêers sluit en binne die **Debug Tab** **Attach to Process...** kies:

![DNSpy Logging - DNSpy Debugging: Dan, om te begin debug, moet jy al die oopgemaakte lêers sluit en binne die Debug Tab Attach to Process kies](<../../images/image (318).png>)

Kies dan **w3wp.exe** om aan die **IIS server** te koppel en klik **attach**:

![DNSpy Logging - DNSpy Debugging: Kies dan w3wp.exe om aan die IIS server te koppel en klik attach](<../../images/image (113).png>)

Noudat ons die proses debug, is dit tyd om dit te stop en al die modules te laai. Klik eers op _Debug >> Break All_ en klik dan op _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses debug, is dit tyd om dit te stop en al die modules te laai. Klik eers op Debug Break All en klik dan op Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses debug, is dit tyd om dit te stop en al die modules te laai. Klik eers op Debug Break All en klik dan op Debug Windows Modules](<../../images/image (834).png>)

Klik op enige module in **Modules** en kies **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Klik op enige module in Modules en kies Open All Modules](<../../images/image (922).png>)

Regsklik op enige module in **Assembly Explorer** en klik **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Regsklik op enige module in Assembly Explorer en klik Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs debug

### Gebruik van IDA

- **Laai rundll32** (64bits in C:\Windows\System32\rundll32.exe en 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Kies die **Windbg** debugger
- Kies "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Kies " Suspend on library load/unload "](<../../images/image (868).png>)

- Stel die **parameters** van die uitvoering op deur die **pad na die DLL** en die funksie wat jy wil roep, in te vul:

![Debugging DLLs - Using IDA: Stel die parameters van die uitvoering op deur die pad na die DLL en die funksie wat jy wil roep, in te vul](<../../images/image (704).png>)

Wanneer jy dan begin debug, **sal die uitvoering gestop word wanneer elke DLL gelaai word**. Wanneer rundll32 jou DLL laai, sal die uitvoering dus gestop word.

Maar hoe kry jy toegang tot die kode van die DLL wat gelaai is? Met hierdie metode weet ek nie hoe nie.

### Gebruik van x64dbg/x32dbg

- **Laai rundll32** (64bits in C:\Windows\System32\rundll32.exe en 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Verander die Command Line** ( _File --> Change Command Line_ ) en stel die pad van die dll en die funksie wat jy wil roep, in, byvoorbeeld: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Verander _Options --> Settings_ en kies "**DLL Entry**".
- **Begin dan die uitvoering**. Die debugger sal by elke dll main stop; op ’n sekere punt sal jy **by die dll Entry van jou dll stop**. Soek van daar af eenvoudig die punte waar jy ’n breakpoint wil plaas.

Let daarop dat wanneer die uitvoering om enige rede in win64dbg gestop word, jy kan sien **in watter kode jy is** deur bo-aan die **win64dbg-venster** te kyk:

![Using IDA - Using x64dbg/x32dbg: Let daarop dat wanneer die uitvoering om enige rede in win64dbg gestop word, jy kan sien in watter kode jy is deur bo-aan die win64dbg-venster te kyk](<../../images/image (842).png>)

Deur hierna te kyk, kan jy sien wanneer die uitvoering gestop is in die dll wat jy wil debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is ’n nuttige program om te vind waar belangrike waardes binne die memory van ’n lopende game gestoor word en dit te verander. Meer inligting in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is ’n front-end/reverse engineering-tool vir die GNU Project Debugger (GDB), gefokus op games. Dit kan egter vir enige reverse-engineering-verwante werk gebruik word.

[**Decompiler Explorer**](https://dogbolt.org/) is ’n web-front-end vir verskeie decompilers. Hierdie webdiens laat jou toe om die uitvoer van verskillende decompilers op klein executables te vergelyk.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debug van ’n shellcode met blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) sal die **shellcode** binne ’n geheuespasie **allocate**, die **memory address** waar die shellcode ge-allocate is aan jou **aandui**, en die uitvoering **stop**.\
Daarna moet jy ’n **debugger aan die proses koppel** (Ida of x64dbg), ’n **breakpoint by die aangeduide memory address plaas** en die uitvoering **hervat**. Op hierdie manier sal jy die shellcode debug.

Die releases github page bevat zips met die compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Jy kan ’n effens aangepaste weergawe van Blobrunner by die volgende link vind. Om dit te compile, **skep jy eenvoudig ’n C/C++-projek in Visual Studio Code, copy en paste die code en build dit**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debug van ’n shellcode met jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)is baie soortgelyk aan blobrunner. Dit sal die **shellcode** binne ’n geheuespasie **allocate** en ’n **ewige loop** begin. Jy moet dan die **debugger aan die proses koppel**, **play start wait 2-5 secs and press stop**, en jy sal jouself binne die **ewige loop** bevind. Spring na die volgende instruksie van die ewige loop, aangesien dit ’n call na die shellcode sal wees, en uiteindelik sal jy die shellcode uitvoer.

![Debug van ’n shellcode met blobrunner - Debug van ’n shellcode met jmp2it: jmp2it is baie soortgelyk aan blobrunner. Dit sal die shellcode binne ’n geheuespasie allocate en ’n...](<../../images/image (509).png>)

Jy kan ’n compiled weergawe van [jmp2it op die releases page aflaai](https://github.com/adamkramer/jmp2it/releases/).

### Debug van shellcode met Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is die GUI van radare. Met Cutter kan jy die shellcode emuleer en dit dinamies inspekteer.

Let daarop dat Cutter jou toelaat om "Open File" en "Open Shellcode" te gebruik. In my geval het dit die shellcode korrek gedecompileer toe ek dit as ’n lêer oopgemaak het, maar nie toe ek dit as ’n shellcode oopgemaak het nie:

![Debug van ’n shellcode met jmp2it - Debug van shellcode met Cutter: Let daarop dat Cutter jou toelaat om "Open File" en "Open Shellcode" te gebruik. In my geval het dit die shellcode korrek...](<../../images/image (562).png>)

Om die emulasie te begin op die plek waar jy wil, stel ’n bp daar en Cutter sal blykbaar outomaties die emulasie van daar af begin:

![Debug van ’n shellcode met jmp2it - Debug van shellcode met Cutter: Om die emulasie te begin op die plek waar jy wil, stel ’n bp daar en Cutter sal blykbaar outomaties...](<../../images/image (589).png>)

![Debug van ’n shellcode met jmp2it - Debug van shellcode met Cutter: Om die emulasie te begin op die plek waar jy wil, stel ’n bp daar en Cutter sal blykbaar outomaties...](<../../images/image (387).png>)

Jy kan byvoorbeeld die stack binne ’n hex dump sien:

![Debug van ’n shellcode met jmp2it - Debug van shellcode met Cutter: Jy kan byvoorbeeld die stack binne ’n hex dump sien](<../../images/image (186).png>)

### Deobfuscating van shellcode en verkryging van uitgevoerde funksies

Jy moet [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) probeer.\
Dit sal jou dinge vertel soos **watter funksies** die shellcode gebruik en of die shellcode homself in memory **decode**.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg beskik ook oor ’n grafiese launcher waar jy die opsies wat jy wil hê, kan kies en die shellcode kan uitvoer

![Debugging van shellcode met Cutter - Deobfuscating van shellcode en verkryging van uitgevoerde funksies: scDbg beskik ook oor ’n grafiese launcher waar jy die opsies wat jy wil hê, kan kies en...](<../../images/image (258).png>)

Die **Create Dump**-opsie sal die finale shellcode dump indien enige verandering dinamies aan die shellcode in die geheue gemaak word (nuttig om die decoded shellcode af te laai). Die **start offset** kan nuttig wees om die shellcode by ’n spesifieke offset te begin. Die **Debug Shell**-opsie is nuttig om die shellcode met die scDbg-terminal te debug (ek vind egter enige van die opsies wat voorheen verduidelik is beter hiervoor, aangesien jy Ida of x64dbg sal kan gebruik).

### Disassembling met CyberChef

Laai jou shellcode-lêer as input op en gebruik die volgende recipe om dit te decompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuscation van MBA obfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation verberg eenvoudige uitdrukkings soos `x + y` agter formules wat rekenkundige (`+`, `-`, `*`) en bitwise-operateurs (`&`, `|`, `^`, `~`, shifts) kombineer. Die belangrike deel is dat hierdie identiteite gewoonlik slegs korrek is onder **fixed-width modular arithmetic**, dus maak carries en overflows saak:
```c
(x ^ y) + 2 * (x & y) == x + y
```
As jy hierdie soort uitdrukking met generiese algebra-nutsmiddels vereenvoudig, kan jy maklik ’n verkeerde resultaat kry omdat die bitwydte-semantiek geïgnoreer is.

### Praktiese werkvloei

1. **Behou die oorspronklike bitwydte** van die geligte code/IR/decompiler-uitvoer (`8/16/32/64` bits).
2. **Klassifiseer die uitdrukking** voordat jy dit probeer vereenvoudig:
- **Lineêr**: geweegde somme van bitwise-atome
- **Semilineêr**: lineêr plus konstante maskers soos `x & 0xFF`
- **Polinoom**: produkte kom voor
- **Gemeng**: produkte en bitwise-logika is vervleg, dikwels met herhaalde subuitdrukkings
3. **Verifieer elke kandidaat-herskrywing** met willekeurige toetsing of ’n SMT-bewys. As die ekwivalensie nie bewys kan word nie, behou die oorspronklike uitdrukking in plaas daarvan om te raai.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is ’n praktiese MBA-vereenvoudiger vir malware-analise en protected-binary reversing. Dit klassifiseer die uitdrukking en stuur dit deur gespesialiseerde pipelines eerder as om een generiese herskrywing-pas op alles toe te pas.<sup>[[1]](#references)[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evalueer die uitdrukking op Boolean inputs, lei ’n signature af, en gebruik verskeie recovery methods soos pattern matching, ANF conversion en coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms word herbou met bit-partitioned reconstruction sodat gemaskerde streke korrek bly.
- **Polynomial/Mixed MBA**: produkte word in cores ontbind, en herhaalde subexpressions kan in temporaries opgelig word voordat die outer relation vereenvoudig word.

Voorbeeld van ’n mixed identity wat dikwels die moeite werd is om te probeer herwin:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Dit kan vereenvoudig word tot:
```c
x * y
```
### Reversing-notas

- Verkies om CoBRA op **geligte IR-uitdrukkings** of decompiler-uitset uit te voer nadat jy die presiese berekening geïsoleer het.
- Gebruik `--bitwidth` eksplisiet wanneer die uitdrukking uit gemaskerde rekenkundige bewerkings of smal registers afkomstig is.
- As jy ’n sterker bewysstap benodig, raadpleeg die plaaslike Z3-notas hier:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA word ook as ’n **LLVM pass plugin** (`libCobraPass.so`) verskaf, wat nuttig is wanneer jy MBA-swaar LLVM IR wil normaliseer voordat latere analysestappe uitgevoer word.
- Residuele gemengde-domein-uitdrukkings wat sensitief is vir carry en nie ondersteun word nie, moet as ’n sein beskou word om die oorspronklike uitdrukking te behou en die carry-pad handmatig te ontleed.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Hierdie obfuscator **wysig alle instruksies na `mov`** (ja, regtig cool). Dit gebruik ook interrupts om uitvoeringsvloeie te verander. Vir meer inligting oor hoe dit werk:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

As jy gelukkig is, sal [demovfuscator](https://github.com/kirschju/demovfuscator) die binary deofuskeer. Dit het verskeie afhanklikhede.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
En [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

As jy aan ’n **CTF deelneem, kan hierdie workaround om die flag te vind** baie nuttig wees: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Om die **entry point** te vind, soek die funksies volgens `::main`, soos in:

![Movfuscator - Rust: Om die entry point te vind, soek die funksies volgens ::main, soos in](<../../images/image (1080).png>)

In hierdie geval is die binary authenticator genoem, so dit is redelik duidelik dat dit die interessante main-funksie is.\
Deur die **name** van die **funksies** wat geroep word te hê, soek daarna op die **Internet** om oor hul **inputs** en **outputs** te leer.

### Herwinning van Rust-stringe uit ELF-firmware

In **Rust ELF**-binaries word baie statiese stringe nie as C-styl NUL-getermineerde pointers verwys nie. ’n Algemene `rustc`-uitleg is ’n pointer/lengte-tupel binne **`.data.rel.ro`** wat na die werklike string-blob wys wat in **`.rodata`** gestoor word:<sup>[[3]](#references)</sup>
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Dit beteken dat `strings` of Ghidra se verstekanalise aangrensende strings kan saamvoeg of kruisverwysings heeltemal kan mis.

Vinnige werksvloei:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Kry die virtuele adres en grootte van **`.rodata`**.
2. Enumereer **`.data.rel.ro`** een woord op ’n slag.
3. Behandel enige waarde binne die **`.rodata`**-adresreeks as ’n kandidaat-stringwyser.
4. Behandel die volgende woord as die kandidaat-lengte.
5. Pas redelikheidsfilters toe (byvoorbeeld, behou lengtes tussen **4** en **100** grepe).
6. Lees presies `length` grepe uit **`.rodata`** in plaas daarvan om te skandeer totdat `0x00` gevind word.

Minimale extractor-logika:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Dit is veral nuttig vir firmware reversing omdat herstelde Rust-strings dikwels **HTTP-roetes, RPC-name, logboodskappe, assertions, lêername, config-sleutels, command handlers en auth-verwante logika** openbaar.

As Ghidra daardie strings mis, voer ’n custom script/plugin uit wat dieselfde heuristiek toepas en string-data by die verwysde `.rodata`-offsets skep. Die gepubliseerde `rust-strings`- en `RustStrings.py`-tools van Pen Test Partners is goeie verwysings om die idee vir ander **word sizes, endianness en section layouts** aan te pas.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Vir Delphi compiled binaries kan jy [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) gebruik.

As jy ’n Delphi binary moet reverse, stel ek voor dat jy die IDA-plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) gebruik.

Druk eenvoudig **ATL+f7** (import python plugin in IDA) en kies die python plugin.

Hierdie plugin sal die binary uitvoer en function names dinamies aan die begin van die debugging oplos. Nadat jy die debugging begin het, druk weer die Start-knoppie (die groen een of f9), en ’n breakpoint sal aan die begin van die werklike code tref.

Dit is ook baie interessant omdat die debugger sal stop in die function wat deur daardie button uitgevoer word as jy ’n button in die grafiese toepassing druk.

## Golang

As jy ’n Golang binary moet reverse, stel ek voor dat jy die IDA-plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) gebruik.

Druk eenvoudig **ATL+f7** (import python plugin in IDA) en kies die python plugin.

Dit sal die names van die functions oplos.

## Gecompileerde Python

Op hierdie bladsy kan jy vind hoe om die Python-code uit ’n ELF/EXE Python compiled binary te kry:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

As jy die **binary** van ’n GBA-game kry, kan jy verskillende tools gebruik om dit te **emulate** en te **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Laai die debug-weergawe af_) - Bevat ’n debugger met koppelvlak
- [**mgba** ](https://mgba.io)- Bevat ’n CLI-debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), onder _**Options --> Emulation Setup --> Controls**_** ** kan jy sien hoe om die Game Boy Advance se **buttons** te druk.

![no$gba-kontrolekonfigurasie wat Game Boy Advance-button-toewysings toon](<../../images/image (581).png>)

Wanneer dit gedruk word, het elke **key ’n waarde** om dit te identifiseer:
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
Dus, in hierdie soort program sal die interessante deel wees **hoe die program die gebruikersinvoer hanteer**. By adres **0x4000130** vind jy die funksie wat algemeen voorkom: **KEYINPUT**.

![Ghidra-aansig van 'n GBA-binêre lêer wat na KEYINPUT by adres 0x4000130 verwys](<../../images/image (447).png>)

In die vorige prent kan jy sien dat die funksie vanuit **FUN_080015a8** geroep word (adresse: _0x080015fa_ en _0x080017ac_).

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
Die laaste **`if`** kontroleer of **`uVar4`** in die **laaste Keys** is en nie die huidige sleutel is nie, ook genoem om 'n knoppie los te laat (die huidige sleutel word in **`uVar1`** gestoor).
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
- Daarna word dit met die **waarde 8** (**START**-knoppie) vergelyk: In die uitdaging kontroleer dit of die kode geldig is om die flag te kry.
- In hierdie geval word die var **`DAT_030000d8`** met 0xf3 vergelyk, en as die waarde dieselfde is, word sekere kode uitgevoer.
- In enige ander gevalle word ’n cont (**DAT_030000d4**) nagegaan. Dit is ’n cont omdat dit onmiddellik nadat die kode binnegegaan is, met 1 verhoog word.\
**A**s dit kleiner as 8 is, word iets gedoen wat behels dat waardes by **`DAT_030000d8`** getel word (basies word die waardes van die gedrukte sleutels by hierdie veranderlike getel solank die cont kleiner as 8 is).

Dus moes jy in hierdie uitdaging, met kennis van die waardes van die knoppies, **’n kombinasie met ’n lengte kleiner as 8 druk waarvan die som 0xf3 is.**<sup>[[6]](#references)</sup>

**Verwysing vir hierdie tutoriaal:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursusse

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## Verwysings

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
