# Reversing-nutsgoed en basiese metodes

{{#include ../../banners/hacktricks-training.md}}

## ImGui-gebaseerde reversing-nutsgoed

Sagteware:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg-outomatisering in user-mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows-kernontfouting

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm-decompiler / Wat-samesteller

Aanlyn:

- Gebruik [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) om van wasm (binêr) na wat (gewone teks) te **decompile**
- Gebruik [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) om van wat na wasm te **compile**
- Jy kan ook [web-wasmdec](https://wwwg.github.io/web-wasmdec/) vir decompilation probeer.

Sagteware:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8-gekasheerde bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Gevirtualiseerde payloads en pasgemaakte VMs

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET-decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is ’n decompiler wat **verskeie formate decompile en ondersoek**, insluitend **biblioteke** (.dll), **Windows-metadata-lêers** (.winmd) en **uitvoerbare lêers** (.exe). Nadat ’n assembly gedecompile is, kan dit as ’n Visual Studio-projek (.csproj) gestoor word.

Die voordeel hiervan is dat as verlore bronkode uit ’n verouderde assembly herstel moet word, hierdie proses tyd kan bespaar. Verder bied dotPeek handige navigasie deur die gedecompilede kode, wat dit een van die perfekte nutsgoed vir **Xamarin-algoritme-analise** maak.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Met ’n omvattende add-in-model en ’n API wat die nutsding uitbrei om aan jou presiese behoeftes te voldoen, bespaar .NET Reflector tyd en vereenvoudig dit ontwikkeling. Kom ons kyk na die talle reverse engineering-dienste wat hierdie nutsding bied:

- Bied insig in hoe die data deur ’n biblioteek of komponent vloei
- Bied insig in die implementering en gebruik van .NET-tale en -raamwerke
- Vind ongedokumenteerde en nie-blootgestelde funksionaliteit om meer uit die gebruikte APIs en tegnologieë te haal.
- Vind afhanklikhede en verskillende assemblies
- Spoor die presiese ligging van foute in jou kode, derdepartykomponente en biblioteke op.
- Ontfout die bronkode van al die .NET-kode waarmee jy werk.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-inprop vir Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Jy kan dit op enige bedryfstelsel gebruik (jy kan dit direk vanuit VSCode installeer; jy hoef nie die git af te laai nie. Klik op **Extensions** en **soek na ILSpy**).\
As jy weer moet **decompile**, **modify** en **recompile**, kan jy [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) of ’n aktief onderhoude fork daarvan, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), gebruik. (**Regskliek -> Modify Method** om iets binne ’n funksie te verander).

### Uitvoeringvrye inspeksie van bestuurde kode met REA

**REA** kan PE/CLI-metadata en CIL inspekteer sonder om die assembly te laai. Begin met die artefakidentiteit, en inspekteer dan lede en verklaarde native grense; dit is nuttig wanneer verdagte oproepe nagegaan word voordat ’n decompiler gebruik word of die program uitgevoer word.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Vir weergawevergelyking gebruik `compare_managed_members` rou CIL-/handtekeningidentiteit en vingerafdrukke van gedekodeerde instruksies, eerder as om metadata-tokens as stabiel tussen bouwe te beskou. ’n P/Invoke-verklaring bewys nie dat native code uitgevoer is nie; `verify_managed_native_boundaries` benodig ooreenstemmende native export- of funksie-Evidence om daardie grens te kontroleer. Hou die artefakdigest, MVID en onopgeloste karterings by die resultaat.<sup>[[17]](#references)</sup>

### DNSpy Logging

Om **DNSpy ’n bietjie inligting in ’n lêer te laat aanteken**, kan jy hierdie brokkie gebruik:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Om code met DNSpy te debug, moet jy:

Verander eers die **Assembly-eienskappe** wat met **debugging** verband hou:

![DNSpy Logging - DNSpy Debugging: Verander eers die Assembly-eienskappe wat met debugging verband hou](<../../images/image (973).png>)

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

Dit is nodig, want as jy dit nie doen nie, sal verskeie **optimisasies** tydens **runtime** op die kode toegepas word. Gevolglik kan dit gebeur dat ’n **break-point nooit getref word nie** of dat sommige **veranderlikes nie bestaan nie** terwyl jy ontfout.

As jou .NET-toepassing deur **IIS** **uitgevoer** word, kan jy dit dan met die volgende herbegin:

```
iisreset /noforce
```

Dan moet jy, om te begin ontfout, al die oopgemaakte lêers sluit en **Attach to Process...** kies in die **Debug Tab**:

![DNSpy Logging - DNSpy Debugging: Dan moet jy, om te begin ontfout, al die oopgemaakte lêers sluit en Attach to Process kies in die Debug Tab](<../../images/image (318).png>)

Kies dan **w3wp.exe** om aan die **IIS-bediener** te koppel en klik **attach**:

![DNSpy Logging - DNSpy Debugging: Kies dan w3wp.exe om aan die IIS-bediener te koppel en klik attach](<../../images/image (113).png>)

Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers op _Debug >> Break All_ en klik dan op _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers op Debug Break All en klik dan op Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses ontfout, is dit tyd om dit te stop en al die modules te laai. Klik eers op Debug Break All en klik dan op Debug Windows Modules](<../../images/image (834).png>)

Klik op enige module onder **Modules** en kies **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Klik op enige module onder Modules en kies Open All Modules](<../../images/image (922).png>)

Regskliek op enige module in **Assembly Explorer** en klik **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Regskliek op enige module in Assembly Explorer en klik Sort Assemblies](<../../images/image (339).png>)

## Java-dekompileerder

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Ontfouting van DLL's

### Using IDA

- **Laai rundll32** (64-bis in C:\Windows\System32\rundll32.exe en 32-bis in C:\Windows\SysWOW64\rundll32.exe)
- Kies die **Windbg**-ontfouter
- Kies "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Kies " Suspend on library load/unload "](<../../images/image (868).png>)

- Stel die **parameters** vir die uitvoering op deur die **pad na die DLL** en die funksie wat jy wil aanroep, in te voer:

![Debugging DLLs - Using IDA: Stel die parameters vir die uitvoering op deur die pad na die DLL en die funksie wat jy wil aanroep, in te voer](<../../images/image (704).png>)

Wanneer jy dan begin ontfout, **sal die uitvoering stop wanneer elke DLL gelaai word**. Wanneer rundll32 jou DLL laai, sal die uitvoering dus stop.

Hierdie metode stop by module-laaigeleenthede, maar om die toegangspunt van die gelaaide DLL te bereik, is minder direk as met die x64dbg-werkvloei hieronder.

### Using x64dbg/x32dbg

- **Laai rundll32** (64-bis in C:\Windows\System32\rundll32.exe en 32-bis in C:\Windows\SysWOW64\rundll32.exe)
- **Verander die Command Line** ( _File --> Change Command Line_ ) en stel die pad van die dll en die funksie wat jy wil aanroep in, byvoorbeeld: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Verander _Options --> Settings_ en kies "**DLL Entry**".
- **Begin dan die uitvoering**; die ontfouter sal by elke dll main stop. Op 'n stadium sal jy **by die DLL Entry van jou dll stop**. Soek van daar af net die plekke waar jy 'n breakpoint wil plaas.

Let daarop dat wanneer die uitvoering om enige rede in win64dbg stop, jy kan sien **in watter kode jy is** deur na die **bokant van die win64dbg-venster** te kyk:

![Using IDA - Using x64dbg/x32dbg: Let daarop dat wanneer die uitvoering om enige rede in win64dbg stop, jy kan sien in watter kode jy is deur na die bokant van die win64dbg-venster te kyk](<../../images/image (842).png>)

Hierdie aanduiding bevestig wanneer die uitvoering binne die DLL wat jy wil ontfout, gestop het.

## GUI-toepassings / Videospeletjies

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes in die geheue van 'n lopende speletjie gestoor word en dit te verander. Meer inligting by:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is 'n front-end-/reverse-engineering-instrument vir die GNU Project Debugger (GDB), met die fokus op speletjies. Dit kan egter vir enigiets rakende reverse engineering gebruik word.

[**Decompiler Explorer**](https://dogbolt.org/) is 'n web-front-end vir verskeie decompilers. Hierdie webdiens laat jou toe om die uitvoer van verskillende decompilers op klein uitvoerbare lêers te vergelyk.

## Bewysgegronde ondersoek van native kode met REA

**REA** bied toegang tot Hopper-, Ghidra- en IDA-ontledings via CLI en MCP. Dit vereis Node.js 22.x (ten minste 22.19), 24.x (ten minste 24.11), of 26+, plus npm. Stel eers 'n bestaande native provider op; kontroleer `rea providers --json` en kies 'n provider uitdruklik wanneer meer as een die teiken ondersteun. Gebruik hieronder 'n waargenome funksienaam of adres uit die inventaris in die plek van `0x1000`.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Begin by ’n kenmerkstring of simbool, volg verwysings en oproepers, en inspekteer dan die gekose funksie-dossier en pseudokode met `rea decompile`. REA bind ’n sessie aan die gekose verskaffer, eerder as om dit ná ’n mislukking stilweg te vervang. Vir herhaalbare navrae hergebruik `--snapshot PATH` slegs ooreenstemmende artefakgrepe, verskaffer, instellings, bewerking en parameters; ’n snapshot is ’n plaaslike kas, nie ’n gestoorde verskafferdatabasis nie. Behou die teruggekeerde Evidence en eksplisiete onbekendes, eerder as om afgeleide paaie of decompilerteks as oorspronklike bronkode te behandel.<sup>[[16]](#references)[[18]](#references)</sup>

Vir JavaScript/Electron-ingangspunte wat na native add-ons lei, sien [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Ontfouting van ’n shellcode met blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) ken die **shellcode** toe, druk sy **geheue-adres** uit en laat uitvoering wag.\
Koppel ’n debugger soos IDA of x64dbg, stel ’n breekpunt by die uitgedrukte adres en hervat uitvoering om die shellcode te ontfout.

Die GitHub-vrystellingsbladsy bevat zip-lêers met die saamgestelde vrystellings: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Jy kan ’n effens aangepaste weergawe van Blobrunner by die volgende skakel vind. Om dit saam te stel, **skep bloot ’n C/C++-projek in Visual Studio Code, kopieer en plak die kode, en bou dit**.


{{#ref}}
blobrunner.md
{{#endref}}

### Ontfouting van ’n shellcode met jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) is soortgelyk aan BlobRunner. Dit ken die shellcode toe en gaan ’n oneindige lus binne. Koppel die debugger, hervat vir **2–5 sekondes**, breek binne daardie lus, en stap na die volgende oproep wat uitvoering na die toegekende shellcode oordra.

![Debugger wat in jmp2it se oneindige lus gestop is, onmiddellik voor die oproep na die toegekende shellcode](<../../images/image (509).png>)

Jy kan ’n saamgestelde weergawe van [jmp2it op die vrystellingsbladsy aflaai](https://github.com/adamkramer/jmp2it/releases/).

### Ontfouting van shellcode met Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is die GUI van radare. Met Cutter kan jy die shellcode emuleer en dit dinamies inspekteer.

Let daarop dat Cutter jou toelaat om “Open File” en “Open Shellcode” te kies. In my geval het dit die shellcode korrek gedekompileer toe ek dit as ’n lêer oopgemaak het, maar nie toe ek dit as shellcode oopgemaak het nie:

![Cutter wat verskillende ontledingsresultate toon wanneer dieselfde grepe as ’n lêer of as shellcode oopgemaak word](<../../images/image (562).png>)

Om die emulasie te begin op die plek wat jy wil, stel daar ’n bp; Cutter sal blykbaar die emulasie outomaties van daar af begin:

![Breekpunt gestel by die verlangde shellcode-ingangspunt voordat Cutter-emulasie begin](<../../images/image (589).png>)

![Cutter-emulator gestop by die gekose shellcode-breekpunt](<../../images/image (387).png>)

Jy kan byvoorbeeld die stapel in ’n heksadesimale dump sien:

![Die geëmuleerde shellcode-stapel in Cutter se heksadesimale dump](<../../images/image (186).png>)

### Deobfuskeering van shellcode en opsporing van uitgevoerde funksies

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

scDbg het ook ’n grafiese lanseerder waarmee jy die gewenste opsies kan kies en die shellcode kan uitvoer

![scDbg se grafiese lanseerder om shellcode-emulasie- en nasporingsopsies te kies](<../../images/image (258).png>)

Die **Create Dump**-opsie stort die finale shellcode uit as enige veranderinge dinamies in die geheue aan die shellcode aangebring word (nuttig om die gedekodeerde shellcode af te laai). Die **start offset** kan nuttig wees om die shellcode by ’n spesifieke offset te begin. Die **Debug Shell**-opsie is nuttig om die shellcode met die scDbg-terminaal te ontfout (ek vind egter enige van die opsies wat vroeër verduidelik is beter hiervoor, aangesien jy Ida of x64dbg kan gebruik).

### Disassemblering met CyberChef

Laai jou shellcode-lêer as invoer op en gebruik die volgende resep om dit te dekompileer: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskering van MBA-obfuskasie

**Mixed Boolean-Arithmetic (MBA)**-obfuskasie verberg eenvoudige uitdrukkings soos `x + y` agter formules wat rekenkundige (`+`, `-`, `*`) en bisgewyse operatore (`&`, `|`, `^`, `~`, skuiwe) meng. Die belangrike punt is dat hierdie identiteite gewoonlik slegs korrek is met **vastewydte-modulêre rekenkunde**, dus maak oordragte en oorlope saak:

```c
(x ^ y) + 2 * (x & y) == x + y
```

As jy hierdie soort uitdrukking met generiese algebragereedskap vereenvoudig, kan jy maklik ’n verkeerde resultaat kry omdat die bitwydte-semantiek geïgnoreer is.<sup>[[1]](#references)</sup>

### Praktiese werkvloei

1. **Behou die oorspronklike bitwydte** van die geligte kode/IR/decompiler-uitvoer (`8/16/32/64` bits).
2. **Klassifiseer die uitdrukking** voordat jy dit probeer vereenvoudig:
   - **Lineêr**: geweegde somme van bitwise-atome
   - **Semilineêr**: lineêr plus konstante maskers soos `x & 0xFF`
   - **Polinoom**: daar kom produkte voor
   - **Gemeng**: produkte en bitwise-logika is ineengestrengel, dikwels met herhaalde subuitdrukkings
3. **Verifieer elke kandidaat-herskrywing** met ewekansige toetsing of ’n SMT-bewys. As die ekwivalensie nie bewys kan word nie, behou die oorspronklike uitdrukking eerder as om te raai.

### Omseil afgeplatte beheer vloei met ’n nou uitvoeringsnit

Dit is dikwels onnodig om die volledige beheervloeigrafiek te herstel. Met control-flow flattening, ondeursigtige predikate, groot dispatchers of MBA-swaar kode, volg verwysings vanaf geënkripteerde blobs en uitvoerbuffers na die kleinste roetine wat hulle transformeer. Reproduseer dan net daardie datasnit, of voer dit onafhanklik uit; die dispatcher is nie deel van die vereiste oplossing as die relevante toestand direk geïnisialiseer kan word nie.<sup>[[7]](#references)</sup>

’n Praktiese werkvloei is:<sup>[[7]](#references)</sup>

1. Inventariseer uitvoerbare en data-afdelings, relocations en kruisverwysings. Dump kandidaat-tabelle uit `.rodata` terwyl hul byte-volgorde en elementwydte behoue bly.
2. Identifiseer die laaste roetine wat die plaintext- of uitvoerbuffer skryf. Teken die insette, verwysde tabelle, ingevoerde aanroepe en vereiste globale toestand aan.
3. Lig slegs daardie bewerkings in ’n Python-model met vaste breedte. As die snit steeds van te veel toestand afhang, roep die roetine onder Unicorn, QEMU of ’n debugger aan en haak irrelevante invoere in plaas daarvan om die hele program te emuleer.
4. Bevestig dat die extractor sy uitvoer werklik uit die verskafde binary aflei: verwyder stilweg terugvalopsies, soek daarin vir ingebedde antwoorde en laat dit teen onbekende builds met veranderde strings, sleutels, identifiseerders, uitlegte en obfuskasiesaadjies loop.

Nuttige opdragte vir ’n eerste ondersoek is:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Bespeur MBA-uitdrukkings wat as konstantes vermom is

’n Skynbaar invoerafhanklike byte-uitdrukking kan sy invoer heeltemal kanselleer. Nadat jy die tabelle onttrek het, evalueer die uitdrukking oor die volledige 8-bis-domein; ’n enkelton-uitsetversameling bewys dat daardie byte konstant is, sonder dat jy die omliggende toestandsmasjien hoef te herkry.<sup>[[7]](#references)</sup>

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

Behou die finale mask omdat die oorspronklike optelling byte-wydte-oorvloei het. Vra vir ’n wyer domein ’n SMT-solver of `f(x1) != f(x2)` bevredigbaar is vir twee simboliese invoere met dieselfde wydte: `unsat` bewys invariansie, terwyl `sat` ’n teenvoorbeeld oplewer en beteken dat die invoer nie weggegooi kan word nie.<sup>[[7]](#references)</sup>

#### Herken omgewingsgebonde dekodering

Anti-analise-kontroles hoef nie te vertak of te laat omval nie. ’n Dekodeerder kan ’n sensorresultaat in ’n sleutelbis, ’n opaque-predicate-konstante of ’n flattened-dispatcher-toestand inmeng, normaal voortgaan en geloofwaardige maar vals plaintext in ’n emulator oplewer. Daarom is dit onvoldoende om slegs sigbare foutvertakkings te patch; volg data-afhanklikhede vanaf omgewingsondersoeke tot by die dekodeerdertoestand, vergelyk dieselfde snit op die egte toestel en emulator, en toets hoe die afdwing van elke sensorresultaat die finale buffer verander.<sup>[[7]](#references)</sup>

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

- **Linear MBA**: CoBRA evalueer die uitdrukking op Boolese invoere, lei ’n handtekening af en probeer verskeie herstelmetodes gelyktydig, soos patroonpassing, ANF-omskakeling en koëffisiëntinterpolasie.
- **Semilinear MBA**: Atome met konstante maskers word met bit-gepartisioneerde rekonstruksie herbou, sodat gemaskerde streke korrek bly.
- **Polynomial/Mixed MBA**: Produkte word in kerne ontbind, en herhaalde subuitdrukkings kan in tydelike veranderlikes opgelig word voordat die buitenste relasie vereenvoudig word.

Voorbeeld van ’n gemengde identiteit wat dikwels die moeite werd is om te probeer herstel:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dit kan tot die volgende vereenvoudig word:

```c
x * y
```

### Reversing-notas

- Verkies om CoBRA op **lifted IR-expressions** of decompiler-uitvoer te laat loop nadat jy die presiese berekening geïsoleer het.
- Gebruik `--bitwidth` uitdruklik wanneer die expression van gemaskerde rekenkunde of smal registers afkomstig is.
- As jy ’n sterker bewysstap nodig het, raadpleeg die plaaslike Z3-notas hier:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA word ook as ’n **LLVM-pass-inprop** (`libCobraPass.so`) verskaf. Dit is nuttig wanneer jy MBA-swaar LLVM IR wil normaliseer voordat latere analise-passe uitgevoer word.
- Ongesteunde carry-sensitiewe gemengde-domein-residuele moet beskou word as ’n teken om die oorspronklike expression te behou en die carry-pad met die hand te ontleed.

## Herstel van XOR-state control-flow flattening

’n OLLVM-styl-flattener kan die huidige basic-block-toestand in twee 64-bis-registers hou en dit met XOR by ’n dispatcher rekonstrueer. Elke oorspronklike block skryf die paar vir sy volgende toestand en spring terug na die dispatcher. ’n Voorwaardelike block kan `CMOVcc` gebruik om een helfte van die paar volgens die CPU-vlae te vervang; as jy dus net die sigbare vertakkingsinstruksies volg, mis jy die twee opvolgers. Anders as ’n indirect-jump-dispatcher kan hierdie vorm deurgaans direkte terugspronge gebruik.<sup>[[19]](#references)[[20]](#references)</sup>

Om die grafiek te herwin, identifiseer die dispatcher se vergelykingstruktuur en die twee state-registers, koppel elke vergelykte XOR-toestand aan sy teikenblock en volg dan die skryfbewerkings na die registerpaar in elke oorspronklike block terug. Sluit vir voorwaardelike skryfbewerkings die vlae-stellende instruksie en albei `CMOVcc`-uitkomste in. Vervang elke block se dispatcher-uitgang met sy opgeloste direkte opvolger of voorwaardelike vertakking; daarna is die dispatcher onbereikbaar sonder dat die binary gelap hoef te word. Dit is ’n volledige-CFG-benadering; as net een decoder saak maak, kan die [noue uitvoeringsnypunt-werkvloei](#bypass-flattened-control-flow-with-a-narrow-execution-slice) hierbo vinniger wees.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) outomatiseer hierdie vorm in Binary Ninja. Kopieer `plugins/DispatchThis` na die Binary Ninja-gebruikersinpropgids en herbegin. Maak **Function Settings** vir die betrokke funksie oop en kies `OLLVM_XOR_64`; as analise nie begin nie, gebruik **Analysis → Reanalyze All Functions**. Hierdie modus herskryf MLIL-beheervloeirande, nie lêergrepe nie, en benodig nie Z3 of die indirect-jump-resolver nie. Dit is op Binary Ninja 5.3.9757+ getoets; dit verwyder nie die dooie toestand-skryfbewerkings per block nie, dus moet dit nie met oorblywende aktiewe oorgange verwar word nie.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Hierdie obfuscator vervang programbewerkings met `mov`-gebaseerde instruksievolgordes en gebruik sein-/uitsonderingshantering om beheervloei te verander. Vir besonderhede:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Vir ondersteunde binaries kan [demovfuscator](https://github.com/kirschju/demovfuscator) die resultaat deobfuscate. Dit het verskeie afhanklikhede.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

En [installeer keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

As jy aan ’n **CTF** deelneem, kan [hierdie omseiling om die flag te vind](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html) baie nuttig wees.

## Rust

Om die **entry point** te vind, soek die funksies vir `::main`, soos in:

![Vind ’n Rust entry point in Ghidra deur funksiename vir dubbelkolon-main te soek](<../../images/image (1080).png>)

In hierdie geval is die binêre lêer authenticator genoem, so dit is redelik duidelik dat dit die interessante hooffunksie is.\
Sodra jy die **name** van die **funksies** wat aangeroep word, het, soek daarna op die **internet** om meer oor hul **insette** en **uitsette** te wete te kom.

### Herstel van Rust-stringe uit ELF-firmware

In **Rust ELF**-binêre lêers word baie statiese stringe nie as C-styl NUL-terminerende wysers verwys nie. ’n Algemene `rustc`-uitleg is ’n **wyser/lengte-tupel** binne **`.data.rel.ro`** wat na die werklike stringblob wys wat in **`.rodata`** gestoor is:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Dit beteken `strings` of Ghidra se verstekontleding kan aangrensende strings saamsmelt of kruisverwysings heeltemal mis.<sup>[[3]](#references)</sup>

Vinnige werkvloei:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Kry die virtuele adres en grootte van **`.rodata`**.
2. Lys **`.data.rel.ro`** een woord op ’n slag.
3. Behandel enige waarde binne die adresreeks van `.rodata` as ’n kandidaat-stringwyser.
4. Behandel die volgende woord as die kandidaat-lengte.
5. Pas sanity filters toe (byvoorbeeld, behou lengtes tussen **4** en **100** grepe).
6. Lees presies `length` grepe uit `.rodata` in plaas daarvan om tot by `0x00` te skandeer.

Minimale extractor-logika:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Dit is veral nuttig wanneer firmware omgekeerd ontleed word, omdat herwonne Rust-strings dikwels **HTTP-roetes, RPC-name, logboodskappe, assertions, lêername, konfigurasiesleutels, opdraghanteerders en logika wat met verifikasie verband hou** openbaar.

As Ghidra hierdie strings mis, voer ’n pasgemaakte script/plugin uit wat dieselfde heuristiek toepas en stringdata skep by die verwysde `.rodata`-offsets. Die gepubliseerde `rust-strings`- en `RustStrings.py`-nutsmiddels van Pen Test Partners is goeie verwysings om die idee by ander **woordgroottes, bytevolgordes en seksie-uitlegte** aan te pas.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Vir Delphi-gecompileerde binêre lêers kan jy [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) gebruik.

As jy ’n Delphi-binêre lêer moet omgekeerd ontleed, stel ek voor dat jy die IDA-plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) gebruik.

Druk **Alt+F7** in IDA om ’n Python-plugin te laai, en kies dan die plugin-lêer.

Hierdie plugin sal die binêre lêer uitvoer en funksiename dinamies aan die begin van die ontfouting bepaal. Nadat die ontfouting begin het, druk weer die Start-knoppie (die groen knoppie of f9) en ’n breekpunt sal aan die begin van die werklike kode tref.

As jy ’n knoppie in die grafiese toepassing druk, kan die ontfouter by die funksie stop wat deur daardie knoppie aangeroep word.

## Golang

Vir gewone Go-binêre lêers kan [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) runtime-strukture herwin en funksiename in IDA verbeter. Laai die Python-plugin met **Alt+F7**.

As jy ’n Golang-binêre lêer moet omgekeerd ontleed, stel ek voor dat jy die IDA-plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) gebruik.

Druk **Alt+F7** in IDA om ’n Python-plugin te laai, en kies dan die plugin-lêer.

Dit sal die name van die funksies bepaal.

### Herwin metadata sonder die simbooltabel

’n Gestroopte Go-uitvoerbare lêer benodig steeds runtime-metadata om programtellers aan funksies te koppel. [GoReSym](https://github.com/mandiant/GoReSym) vind en ontleed strukture soos `pclntab` en `moduledata` deur kode te gebruik wat van die Go-runtime afgelei is. Dit kan funksiegrense, name, bronpaaie, tipes en boubesonderhede herwin sonder om op die konvensionele simbooltabel staat te maak.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

'n Obfuscator kan daardie strukture bruikbaar laat terwyl die herstelde name vervang word. Garble hash byvoorbeeld identifiseerders en pakketpaaie en verwyder bou-, module- en ontfoutingsinligting.<sup>[[12]](#references)</sup> Die geobfuskeerde pakkettoken moet konsekwent bly tussen funksies van daardie pakket. Groepeer funksies volgens die herhaalde token, lei een pakket af uit sy callees, stringe en API's, en ken dan daardie pakketetiket aan die hele groep toe.<sup>[[13]](#references)</sup>

### Herstel Garble-name met GoResolver

[GoResolver](https://github.com/volexity/GoResolver) kombineer runtime-simboolonttrekking met die generering van skoon verwysings en CFG-ooreenstemming (control-flow-graph). Gebruik hierdie volgorde:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifiseer die samestellerversie.** Probeer eers `BuildInfo` en ingebedde weergawestringe. As die obfuscator dit verwyder het, vergelyk gedeeltes van die gebundelde Go-runtime met runtime-verwysings van spesifieke weergawes. In Volexity se toetse was ongeveer `2%` van die runtime genoeg om groot Go-weergawes te onderskei. Beskou dit as 'n empiriese optimalisering, nie as 'n universele drempel nie.<sup>[[13]](#references)</sup>
2. **Bou ooreenstemmende verwysings.** Genereer skoon binaries vir die geïdentifiseerde Go-weergawe, teikenargitektuur en waarskynlike libraries. 'n Ooreenstemmende toolchain verminder CFG-verskille wat deur die samesteller gegenereer word.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Vergelyk funksies.** GoGrapher pas funksie-CFG's by mekaar en lewer genormaliseerde tellings van `0.0` tot `1.0`. Die passing van basiese blokke is gebaseer op 'n geweegde vergelyking van soortgelyke instruksies. Ooreenstemmings met hoë sekerheid koppel gerandomiseerde funksies aan die skoon implementering. Swakker ooreenstemmings kan steeds 'n pakket of module identifiseer.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Valideer en voer in.** Bevestig voorgestelde name met oproepverhoudings, konstantes, stringe en newe-effekte, en voer dan die JSON-verslag in met die GoResolver-inprop vir IDA of Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Die verstekdrempel vir beduidende passings is `0.9`. Die `--extract`- en `--graph`-skakelaars kan enige van die fases afsonder, terwyl die verstek albei uitvoer omdat die herstelde runtime-metadata en CFG-bewyse mekaar aanvul.<sup>[[10]](#references)</sup> CFG-tellings is heuristies: inlining, bouvlae, argitektuur en verskille in biblioteekweergawes kan die grafiekvorm verander, dus moet onopgeloste funksies behou word eerder as om name met lae sekerheid af te dwing.<sup>[[13]](#references)</sup>

### Herstel van die Go-stringtabel

Go-binêres plaas stringgrepe van elke gekoppelde pakket in een aaneenlopende tabel. Die inskrywings word nie met NUL beëindig nie, en runtime-strukture stel nie die basis of grootte van die tabel bloot nie. Die samesteller rangskik inskrywings egter eers volgens lengte en dan alfabeties oor bedryfstelsels en argitekture heen. Nadat een inskrywing gevind is, kan ’n ontleder dus deur aangrensende inskrywings loop en data-kruisverwysings gebruik om stringe aan kode te koppel.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) outomatiseer hierdie werkvloei in IDA Pro en Ghidra. Laat outomatiese ontleding eers klaarmaak, omdat die plugin op kruisverwysings na datasemente staatmaak. Die verstekanker is die runtime-string `entersyscall`; daarna kan dit in enige rigting soek, die herstelde stringe in die databasis definieer en ’n JSON-kartering van stringe na verwysende funksies uitvoer.<sup>[[14]](#references)</sup>

Filtreer die verslag volgens die pakket van die verwysende funksie om toepassings- of malware-kode van gekoppelde biblioteekruis te skei. Hierdie tegniek kan nie letterlike waardes herstel wat deur obfuskasie vernietig is nie, soos Garble se `-literals`-transformasie. Dit kan steeds runtime-stringe organiseer wat onbehef is.<sup>[[14]](#references)[[15]](#references)</sup>

### Herstel van Go-runtime-tipes

Go bevat runtime-tipe-inligting wat deur kenmerke soos garbage collection gebruik word. Wanneer bou-inligting verwyder is of die disassembler nie hierdie metadata ontleed nie, kan dit lyk asof instruksies arbitrêre data-adresse laai en bly die teikenstreek ongetipeer. Deur die metadata te herstel, word hierdie adresse leesbare tipeverwysings en word dit makliker om pakketvermoëns te verstaan.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) kan simbole onttrek en runtime-tipes in ’n JSON-verslag ontleed. Die huidige CLI gebruik die `resolve`-subopdrag:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Die `-y`/`--types`-opsie aktiveer tipe-ontleding. Voer die verslag met GoResolver se IDA Pro- of Ghidra-inprop in om die herstelde tipes te definieer en hul verwysings in die ontledingsdatabasis toe te pas. In die verslagformaat wat met hierdie funksie bekendgestel is, laat die weglating van `-y` die RTTI-adres en herstelde-tipes-lede op null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver ondersteun PE-, ELF- en Mach-O-monsters vir x86, AMD64, ARM en ARM64, dus geld dieselfde werkvloei vir Go-binêre lêers van Windows, Linux en macOS.<sup>[[10]](#references)</sup>

## Gekompileerde Python

Op hierdie bladsy kan jy vind hoe om die Python-kode uit 'n ELF/EXE Python-binêre lêer te kry:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

As jy die **binary** van 'n GBA-speletjie kry, kan jy verskillende nutsgoed gebruik om dit te **emuleer** en **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Laai die debug-weergawe af_) - Bevat 'n debugger met 'n koppelvlak
- [**mgba** ](https://mgba.io)- Bevat 'n CLI-debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-inprop
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-inprop

In [**no$gba**](https://problemkaputt.de/gba.htm), by _**Options --> Emulation Setup --> Controls**_** ** kan jy sien hoe om die Game Boy Advance-**knoppies** te druk

![no$gba-kontrolekonfigurasie wat die Game Boy Advance-knoppiekarterings wys](<../../images/image (581).png>)

Wanneer dit gedruk word, het elke **sleutel 'n waarde** wat dit identifiseer:

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

So, in hierdie soort program sal die interessante deel wees **hoe die program die gebruiker se invoer hanteer**. By die adres **0x4000130** vind jy die funksie wat algemeen voorkom: **KEYINPUT**.

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

Die laaste if kontroleer of **`uVar4`** tussen die **laaste sleutels** is en nie die huidige sleutel is nie; dit staan ook bekend as om ’n knoppie los te laat (die huidige sleutel word in **`uVar1`** gestoor).

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

In die vorige kode kan jy sien dat ons **uVar1** (die plek waar die **waarde van die gedrukte knoppie** gestoor word) met sommige waardes vergelyk:

- Eerstens word dit met die **waarde 4** (**SELECT**-knoppie) vergelyk: In die challenge vee hierdie knoppie die skerm uit
- Daarna vergelyk dit die waarde met **8** (die **START**-knoppie); in hierdie challenge kyk daardie roete of die ingevoerde kode geldig is.
  - In hierdie geval word die var **`DAT_030000d8`** met 0xf3 vergelyk, en as die waarde ooreenstem, word sekere kode uitgevoer.
- In elke ander geval word ’n teller (`DAT_030000d4`) nagegaan en verhoog.\
  Solank die teller kleiner as 8 is, word die waardes van die gedrukte knoppies in `DAT_030000d8` bymekaar getel.

Dus moes jy in hierdie challenge, met kennis van die knoppiewaardes, **’n kombinasie met ’n lengte kleiner as 8 druk waarvan die som 0xf3 is.**

**Verwysing vir hierdie tutoriaal:** [argiefweergawe van die Nostalgia-challenge-skrywe](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [6] [Nostalgia - GBA-reversing-tutoriaal (argiefweergawe)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Om AI-gesteunde reverse engineering te stuit, of ten minste te probeer](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [’n Benadering om beheervloeigrafieke te vergelyk op grond van basiese blokpassing](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver-bewaarplek](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble-obfuskeringsmeganisme](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Gebruik van beheervloeigraaf-ooreenkomste om Golang-binêre lêers outomaties te deobfuskeer](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor-bewaarplek](https://github.com/volexity/GoStringExtractor)
- [15] [Kry hulle: Opdaterings aan Volexity se Golang-gereedskap](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [REA-ontleding van bestuurde kode](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI- en bewysgids](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja-werkvloei vir die ontvouing van beheervloei](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF-zero-dag-indringing, Java-laaier, webshell en AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
{{#include ../../banners/hacktricks-training.md}}
