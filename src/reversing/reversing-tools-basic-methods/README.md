# Reversing-gereedskap en basiese metodes

{{#include ../../banners/hacktricks-training.md}}

## ImGui-gebaseerde reversing-gereedskap

Sagteware:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg-outomatisering in gebruikersmodus

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows-kernelfoutopsporing

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm-decompiler / Wat-samesteller

Aanlyn:

- Gebruik [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) om van wasm (binêr) na wat (gewone teks) te **decompileer**
- Gebruik [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) om wat na wasm te **compileer**
- Jy kan ook [web-wasmdec](https://wwwg.github.io/web-wasmdec/) vir decompilering probeer.

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

## .NET-decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is ’n decompiler wat verskeie formate **decompileer en ondersoek**, insluitend **biblioteke** (.dll), **Windows-metadata-lêers** (.winmd) en **uitvoerbare lêers** (.exe). Nadat dit gedecompileer is, kan ’n assembly as ’n Visual Studio-projek (.csproj) gestoor word.

Die voordeel hiervan is dat hierdie stap tyd kan bespaar as verlore bronkode uit ’n verouderde assembly herstel moet word. Verder bied dotPeek handige navigasie deur die gedecompileerde kode, wat dit een van die ideale gereedskap vir **Xamarin-algoritme-ontleding** maak.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Met ’n omvattende byvoegmodel en ’n API wat die gereedskap uitbrei om aan jou presiese behoeftes te voldoen, bespaar .NET Reflector tyd en vereenvoudig dit ontwikkeling. Kom ons kyk na die talle reverse engineering-dienste wat hierdie gereedskap bied:

- Bied insig in hoe data deur ’n biblioteek of komponent vloei
- Bied insig in die implementering en gebruik van .NET-tale en -raamwerke
- Vind ongedokumenteerde en nie-blootgestelde funksionaliteit om meer uit die gebruikte API’s en tegnologieë te haal.
- Vind afhanklikhede en verskillende assemblies
- Spoor die presiese ligging van foute in jou kode, derdepartykomponente en biblioteke op.
- Debug die bronkode van al die .NET-kode waarmee jy werk.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-inprop vir Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Jy kan dit op enige bedryfstelsel gebruik (jy kan dit direk vanuit VSCode installeer; jy hoef nie die git af te laai nie. Klik op **Extensions** en **soek na ILSpy**).\
As jy weer wil **decompileer**, **wysig** en **recompileer**, kan jy [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) of ’n aktief onderhoude fork daarvan, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), gebruik. (**Regskliek -> Modify Method** om iets binne ’n funksie te verander).

### Inspeksie van managed kode sonder uitvoering met REA

**REA** kan PE/CLI-metadata en CIL inspekteer sonder om die assembly te laai. Begin met die artefak se identiteit en inspekteer dan lede en verklaarde native grense; dit is nuttig wanneer verdagte oproepe nagegaan word voordat ’n decompiler gebruik word of die program uitgevoer word.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Vir weergawevergelyking gebruik `compare_managed_members` rou CIL-/handtekeningidentiteit en vingerafdrukke van gedekodeerde instruksies, eerder as om metadata-tokens as stabiel tussen bouwe te beskou. ’n P/Invoke-deklarasie bewys nie dat native kode uitgevoer is nie; `verify_managed_native_boundaries` benodig ooreenstemmende native-uitvoer of funksie-`Evidence` om daardie grens na te gaan. Hou die artifact-digest, MVID en onopgeloste karterings saam met die resultaat.<sup>[[17]](#references)</sup>

### DNSpy Logging

Om **DNSpy ’n bietjie inligting in ’n lêer te laat aanteken**, kan jy hierdie brokkie gebruik:

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Stoor dan die nuwe lêer via _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Dit is nodig, want as jy dit nie doen nie, sal verskeie **optimaliserings** tydens **runtime** op die kode toegepas word, en dit kan gebeur dat ’n **breakpoint nooit getref word nie** of dat sommige **veranderlikes nie bestaan nie**.

As jou .NET-toepassing dan deur **IIS** **uitgevoer** word, kan jy dit met die volgende **herbegin**:

```
iisreset /noforce
```

Dan, om te begin debuggen, moet jy al die oopgemaakte lêers sluit en in die **Debug Tab** **Attach to Process...** kies:

![DNSpy Logging - DNSpy Debugging: Dan, om te begin debuggen, moet jy al die oopgemaakte lêers sluit en in die Debug Tab Attach to Process kies](<../../images/image (318).png>)

Kies dan **w3wp.exe** om aan die **IIS server** te koppel en klik **attach**:

![DNSpy Logging - DNSpy Debugging: Kies dan w3wp.exe om aan die IIS server te koppel en klik attach](<../../images/image (113).png>)

Noudat ons die proses debug, is dit tyd om dit te stop en al die modules te laai. Klik eers **Debug >> Break All** en klik dan **_Debug >> Windows >> Modules_**:

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses debug, is dit tyd om dit te stop en al die modules te laai. Klik eers op Debug Break All en klik dan op Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Noudat ons die proses debug, is dit tyd om dit te stop en al die modules te laai. Klik eers op Debug Break All en klik dan op Debug Windows Modules](<../../images/image (834).png>)

Klik op enige module in **Modules** en kies **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Klik op enige module in Modules en kies Open All Modules](<../../images/image (922).png>)

Regsklik op enige module in **Assembly Explorer** en klik **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Regsklik op enige module in Assembly Explorer en klik Sort Assemblies](<../../images/image (339).png>)

## Java-decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL's debuggen

### Gebruik IDA

- **Laai rundll32** (64-bis in C:\Windows\System32\rundll32.exe en 32-bis in C:\Windows\SysWOW64\rundll32.exe)
- Kies die **Windbg**-debugger
- Kies "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Kies " Suspend on library load/unload "](<../../images/image (868).png>)

- Stel die **parameters** vir die uitvoering in deur die **pad na die DLL** en die funksie wat jy wil aanroep, in te vul:

![Debugging DLLs - Using IDA: Stel die parameters vir die uitvoering in deur die pad na die DLL en die funksie wat jy wil aanroep, in te vul](<../../images/image (704).png>)

Wanneer jy dan begin debuggen, **sal die uitvoering stop wanneer elke DLL gelaai word**. Dus, wanneer rundll32 jou DLL laai, sal die uitvoering stop.

Hierdie metode stop by modulelaaigebeure, maar om die ingangspunt van die gelaaide DLL te bereik, is minder direk as met die x64dbg-werkvloei hieronder.

### Gebruik x64dbg/x32dbg

- **Laai rundll32** (64-bis in C:\Windows\System32\rundll32.exe en 32-bis in C:\Windows\SysWOW64\rundll32.exe)
- **Verander die Command Line** ( _File --> Change Command Line_ ) en stel die pad na die dll en die funksie wat jy wil aanroep in, byvoorbeeld: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Verander _Options --> Settings_ en kies "**DLL Entry**".
- **Begin dan die uitvoering**; die debugger sal by elke dll main stop. Op 'n stadium sal jy **by die DLL Entry van jou dll stop**. Soek van daar af na die punte waar jy 'n breakpoint wil plaas.

Let daarop dat wanneer die uitvoering om enige rede in win64dbg stop, jy kan sien **in watter kode jy is** deur boaan die win64dbg-venster te kyk:

![Using IDA - Using x64dbg/x32dbg: Let daarop dat wanneer die uitvoering om enige rede in win64dbg stop, jy kan sien in watter kode jy is deur boaan die win64dbg-venster te kyk](<../../images/image (842).png>)

Hierdie aanduider bevestig wanneer die uitvoering binne die DLL wat jy wil debug, gestop het.

## GUI-toepassings / videospeletjies

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes in die geheue van 'n lopende speletjie gestoor word en om dit te verander. Meer inligting by:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is 'n front-end-/reverse-engineering-nutsding vir die GNU Project Debugger (GDB), gefokus op speletjies. Dit kan egter vir enige reverse-engineering-verwante werk gebruik word.

[**Decompiler Explorer**](https://dogbolt.org/) is 'n web-front-end vir verskeie decompilers. Hierdie webdiens laat jou toe om die uitvoer van verskillende decompilers op klein uitvoerbare lêers te vergelyk.

## Bewysgesteunde native ondersoek met REA

**REA** bied toegang tot Hopper-, Ghidra- en IDA-ontledings via CLI en MCP. Dit vereis Node.js 22.x (minstens 22.19), 24.x (minstens 24.11), of 26+, plus npm. Stel eers 'n bestaande native provider op; gaan `rea providers --json` na en kies 'n provider uitdruklik wanneer meer as een die teiken ondersteun. Gebruik hieronder 'n waargenome funksienaam of adres uit die inventaris in plaas van `0x1000`.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Begin by ’n feature-string of simbool, volg verwysings en aanroepers, en inspekteer dan die geselekteerde funksie-dossier en pseudokode met `rea decompile`. REA bind ’n sessie aan die geselekteerde provider, eerder as om dit stilweg ná ’n fout te vervang. Vir herhaalbare navrae hergebruik `--snapshot PATH` slegs ooreenstemmende artefakgrepe, provider, instellings, bewerking en parameters; ’n snapshot is ’n plaaslike kas, nie ’n gestoorde provider-databasis nie. Bewaar die teruggestuurde Evidence en uitdruklike onbekendes eerder as om afgeleide paaie of decompiler-teks as oorspronklike bronkode te beskou.<sup>[[16]](#references)[[18]](#references)</sup>

Vir JavaScript/Electron-ingangspunte wat na native add-ons lei, sien [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Ontfouting van ’n shellcode met blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) allokeer die **shellcode**, druk sy **geheue-adres** af en laat uitvoering wag.\
Koppel ’n debugger soos IDA of x64dbg aan, stel ’n breakpoint by die afgedrukte adres en hervat uitvoering om die shellcode te ontfout.

Die GitHub-vrystellingsbladsy bevat zip-lêers met die saamgestelde vrystellings: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Jy kan ’n effens aangepaste weergawe van Blobrunner by die volgende skakel vind. Om dit saam te stel, **skep eenvoudig ’n C/C++-projek in Visual Studio Code, kopieer en plak die kode en bou dit**.


{{#ref}}
blobrunner.md
{{#endref}}

### Ontfouting van ’n shellcode met jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) is soortgelyk aan BlobRunner. Dit allokeer die shellcode en betree ’n oneindige lus. Koppel die debugger aan, hervat vir **2–5 sekondes**, onderbreek binne daardie lus en stap na die daaropvolgende aanroep wat uitvoering na die geallokeerde shellcode oordra.

![Debugger onderbreek in jmp2it se oneindige lus, onmiddellik voor die aanroep na die geallokeerde shellcode](<../../images/image (509).png>)

Jy kan ’n saamgestelde weergawe van [jmp2it op die vrystellingsbladsy aflaai](https://github.com/adamkramer/jmp2it/releases/).

### Ontfouting van shellcode met Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is die GUI van radare. Met Cutter kan jy die shellcode emuleer en dit dinamies inspekteer.

Let daarop dat Cutter jou toelaat om “Open File” en “Open Shellcode” te kies. In my geval het dit die shellcode korrek gedecompileer toe ek dit as ’n lêer oopgemaak het, maar nie toe ek dit as ’n shellcode oopgemaak het nie:

![Cutter wys verskillende ontledingsresultate wanneer dieselfde grepe as ’n lêer of as shellcode oopgemaak word](<../../images/image (562).png>)

Om die emulasie te begin op die plek wat jy wil hê, stel ’n bp daar; Cutter sal blykbaar die emulasie outomaties van daar af begin:

![’n Breekpunt word by die verlangde shellcode-ingang gestel voordat Cutter se emulasie begin](<../../images/image (589).png>)

![Cutter-emulator onderbreek by die geselekteerde shellcode-breekpunt](<../../images/image (387).png>)

Jy kan byvoorbeeld die stack in ’n heksstort sien:

![Die geëmuleerde shellcode-stack word in Cutter se heksstort bekyk](<../../images/image (186).png>)

### Deobfuskering van shellcode en verkryging van uitgevoerde funksies

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

scDbg beskik ook oor ’n grafiese lanseerder waar jy die gewenste opsies kan kies en die shellcode kan uitvoer

![scDbg-grafiese lanseerder om shellcode-emulering- en nasporingsopsies te kies](<../../images/image (258).png>)

Die **Create Dump**-opsie sal die finale shellcode dump as enige veranderinge dinamies in die geheue aan die shellcode aangebring word (nuttig om die gedekodeerde shellcode af te laai). Die **start offset** kan nuttig wees om die shellcode by ’n spesifieke offset te begin. Die **Debug Shell**-opsie is nuttig om die shellcode met die scDbg-terminaal te debug (ek vind egter enige van die opsies wat voorheen verduidelik is beter hiervoor, aangesien jy Ida of x64dbg sal kan gebruik).

### Disassemblering met CyberChef

Laai jou shellcode-lêer as invoer op en gebruik die volgende resep om dit te disassembleer: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskering van MBA-obfuskering

**Mixed Boolean-Arithmetic (MBA)**-obfuskering verberg eenvoudige uitdrukkings soos `x + y` agter formules wat rekenkundige (`+`, `-`, `*`) en bitgewys-operateurs (`&`, `|`, `^`, `~`, verskuiwings) meng. Die belangrike punt is dat hierdie identiteite gewoonlik slegs korrek is onder **vaste-breedte-modulêre rekenkunde**, dus maak oordragte en oorlope saak:

```c
(x ^ y) + 2 * (x & y) == x + y
```

As jy hierdie soort uitdrukking met generiese algebragereedskap vereenvoudig, kan jy maklik ’n verkeerde resultaat kry omdat die bitwydte-semantiek geïgnoreer is.<sup>[[1]](#references)</sup>

### Praktiese werkvloei

1. **Behou die oorspronklike bitwydte** van die geligte kode/IR/dekompileerderuitset (`8/16/32/64` bits).
2. **Klassifiseer die uitdrukking** voordat jy dit probeer vereenvoudig:
   - **Lineêr**: geweegde somme van bitgewys-atome
   - **Semilineêr**: lineêr plus konstante maskers soos `x & 0xFF`
   - **Polinoom**: produkte kom voor
   - **Gemeng**: produkte en bitgewys-logika is verweef, dikwels met herhaalde subuitdrukkings
3. **Verifieer elke kandidaat-herskrywing** met ewekansige toetsing of ’n SMT-bewys. As die ekwivalensie nie bewys kan word nie, behou die oorspronklike uitdrukking eerder as om te raai.

### Omseil afgeplatte beheer-vloei met ’n nou uitvoeringsnit

Dit is dikwels onnodig om die volledige beheer-vloeigrafiek te herwin. Met control-flow flattening, ondeursigtige predikate, groot dispatchers of kode met baie MBA, volg verwysings vanaf geënkripteerde blobs en uitsetbuffers na die kleinste roetine wat hulle transformeer. Reproduseer dan net daardie data-vloeisnit, of voer dit onafhanklik uit; die dispatcher is nie deel van die vereiste oplossing as die relevante toestand direk geïnisialiseer kan word nie.<sup>[[7]](#references)</sup>

’n Praktiese werkvloei is:<sup>[[7]](#references)</sup>

1. Inventariseer uitvoerbare en data-afdelings, relocations en kruisverwysings. Dump kandidaat-tabelle uit `.rodata` en behou hul grepevolgorde en elementwydte.
2. Identifiseer die laaste roetine wat na die plaintext- of uitsetbuffer skryf. Teken sy invoere, verwysde tabelle, geïmporteerde aanroepe en vereiste globale toestand aan.
3. Lig net daardie bewerkings in ’n Python-model met vaste wydte. As die snit steeds van te veel toestand afhang, roep die roetine onder Unicorn, QEMU of ’n debugger aan en hook irrelevante imports eerder as om die hele program na te boots.
4. Bevestig dat die extractor sy uitset werklik uit die verskafte binary aflei: verwyder stil terugvalopsies, deursoek dit vir ingebedde antwoorde en toets dit teen onbekende builds met veranderde stringe, sleutels, identifiseerders, uitlegte en obfuscation-sade.

Nuttige opdragte vir ’n eerste deurgang is:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Bespeur MBA-uitdrukkings wat vermomde konstantes is

’n Oënskynlik invoerafhanklike byte-uitdrukking kan sy invoer heeltemal kanselleer. Nadat jy die tabelle onttrek het, evalueer die uitdrukking oor die volledige 8-bis-domein; ’n singleton-uitvoerversameling bewys dat daardie byte konstant is, sonder dat jy die omliggende toestandmasjien hoef te herwin.<sup>[[7]](#references)</sup>

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

Behou die finale masker, want die oorspronklike optelling het byte-wydte-oorvloei. Vra vir ’n wyer domein ’n SMT-solver of `f(x1) != f(x2)` bevredigbaar is vir twee simboliese insette met dieselfde wydte: `unsat` bewys invariansie, terwyl `sat` ’n teenvoorbeeld oplewer en beteken dat die inset nie weggegooi kan word nie.<sup>[[7]](#references)</sup>

#### Herken omgewingsgebonde dekodering

Anti-analise-kontroles hoef nie te vertak of te crash nie. ’n Dekodeerder kan ’n sensorresultaat by ’n sleutelbis, ’n opaque-predicate-konstante of die toestand van ’n platgemaakte dispatcher inmeng, normaal voortgaan en geloofwaardige maar vals plaintext in ’n emulator oplewer. Daarom is dit nie genoeg om slegs sigbare foutvertakkings te patch nie; volg data-afhanklikhede vanaf omgewingsprobes na die dekodeerdertoestand, vergelyk dieselfde gedeelte op die egte toestel en emulator, en toets hoe die forsering van elke sensorresultaat die finale buffer verander.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is ’n praktiese MBA-simplifiseerder vir malware-analise en die omgekeerde ontleding van beskermde binaries. Dit klassifiseer die uitdrukking en stuur dit deur gespesialiseerde pipelines, eerder as om een generiese herskryfpas op alles toe te pas.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evalueer die uitdrukking op Boolese insette, lei ’n handtekening af en probeer verskeie herstelmetodes in parallel, soos patroonpassing, ANF-omskakeling en koëffisiëntinterpolasie.
- **Semilinear MBA**: atome met konstante maskers word met bitpartisie-herkonstruksie herbou sodat gemaskerde streke korrek bly.
- **Polynomial/Mixed MBA**: produkte word in kerne ontbind, en herhaalde subuitdrukkings kan in tydelike veranderlikes geplaas word voordat die buitenste relasie vereenvoudig word.

Voorbeeld van ’n gemengde identiteit wat dikwels die moeite werd is om te probeer herwin:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dit kan vereenvoudig word tot:

```c
x * y
```

### Reversing-notas

- Verkies om CoBRA op **geligte IR-uitdrukkings** of decompiler-uitvoer te laat loop nadat jy die presiese berekening geïsoleer het.
- Gebruik `--bitwidth` uitdruklik wanneer die uitdrukking van gemaskerde rekenkunde of smal registers afkomstig is.
- As jy ’n sterker bewysstap nodig het, raadpleeg die plaaslike Z3-notas hier:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA word ook as ’n **LLVM-pass-inprop** (`libCobraPass.so`) verskaf, wat nuttig is wanneer jy MBA-swaar LLVM IR wil normaliseer voordat latere ontledingspasses uitgevoer word.
- Ongesteunde gemengde-domein-residuele wat sensitief is vir carry, moet beskou word as ’n teken om die oorspronklike uitdrukking te behou en die carry-pad met die hand te ontleed.

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

As jy aan ’n **CTF** deelneem, kan hierdie ompad om die flag te vind baie nuttig wees: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Om die **ingangspunt** te vind, soek in die funksies na `::main`, soos in:

![Vind ’n Rust-ingangspunt in Ghidra deur na funksiename met dubbelkolon-main te soek](<../../images/image (1080).png>)

In hierdie geval is die binêre lêer authenticator genoem, so dis redelik duidelik dat dit die interessante hooffunksie is.\
As jy die **name** van die aangeroepte **funksies** het, soek daarna op die **Internet** om meer oor hul **insette** en **uitsette** te wete te kom.

### Herstel van Rust-stringe uit ELF-firmware

In **Rust ELF**-binêre lêers word baie statiese stringe nie as C-styl NUL-terminerende wysers verwys nie. ’n Algemene `rustc`-uitleg is ’n **wyser/lengte-tupel** binne **`.data.rel.ro`** wat na die werklike stringblok in **`.rodata`** wys:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Dit beteken dat `strings` of die verstek Ghidra-analise aangrensende stringe kan saamsmelt of kruisverwysings heeltemal kan mis.<sup>[[3]](#references)</sup>

Vinnige werkvloei:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Kry die virtuele adres en grootte van **`.rodata`**.
2. Lys **`.data.rel.ro`** een word op ’n slag.
3. Behandel enige waarde binne die `.rodata`-adresreeks as ’n kandidaat-stringwyser.
4. Behandel die volgende word as die kandidaat-lengte.
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

Dit is veral nuttig vir firmware reversing, want herwonne Rust-stringe onthul dikwels **HTTP-roetes, RPC-name, logboodskappe, assertions, lêername, config-sleutels, command handlers en auth-verwante logika**.

As Ghidra hierdie stringe miskyk, laat loop ’n pasgemaakte script/plugin wat dieselfde heuristiek toepas en stringdata skep by die verwysde `.rodata`-offsets. Die gepubliseerde `rust-strings`- en `RustStrings.py`-nutsgoed van Pen Test Partners is goeie verwysings om die idee by ander **woordgroottes, endianness en seksie-uitlegte** aan te pas.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Vir Delphi-gecompileerde binaries kan jy [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) gebruik.

As jy ’n Delphi-binary moet reverse, stel ek voor dat jy die IDA-plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) gebruik.

Druk **Alt+F7** in IDA om ’n Python-plugin te laai, en kies dan die plugin-lêer.

Hierdie plugin sal die binary uitvoer en funksiename dinamies oplos wanneer debugging begin. Nadat debugging begin het, druk weer die Start-knoppie (die groen een of f9), en ’n breakpoint sal aan die begin van die werklike kode tref.

As jy ’n knoppie in die grafiese toepassing druk, kan die debugger by die funksie stop wat deur daardie knoppie opgeroep word.

## Golang

Vir gewone Go-binaries kan [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) runtime-strukture herwin en funksiename in IDA verbeter. Laai die Python-plugin met **Alt+F7**.

As jy ’n Golang-binary moet reverse, stel ek voor dat jy die IDA-plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) gebruik.

Druk **Alt+F7** in IDA om ’n Python-plugin te laai, en kies dan die plugin-lêer.

Dit sal die name van die funksies oplos.

### Herwin metadata sonder die simbooltabel

’n Gestriptte Go-uitvoerbare lêer benodig steeds runtime-metadata om programtellers aan funksies te koppel. [GoReSym](https://github.com/mandiant/GoReSym) vind en ontleed strukture soos `pclntab` en `moduledata` met behulp van kode wat van die Go-runtime afgelei is. Dit kan funksiegrense, name, bronpaaie, tipes en boubesonderhede herwin sonder om op die konvensionele simbooltabel staat te maak.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

’n Obfuscator kan daardie strukture bruikbaar laat terwyl die herstelde name vervang word. Garble has byvoorbeeld identifiseerders en pakketpaaie en verwyder build-, module- en debug-inligting.<sup>[[12]](#references)</sup> Die geobfuskeerde pakkettoken moet konsekwent bly oor funksies uit daardie pakket. Groepeer funksies volgens die herhaalde token, lei een pakket af uit sy callees, strings en API’s, en ken dan daardie pakketetiket aan die hele groep toe.<sup>[[13]](#references)</sup>

### Herstel Garble-name met GoResolver

[GoResolver](https://github.com/volexity/GoResolver) kombineer runtime-simboolonttrekking met die generering van skoon verwysings en die vergelyking van beheervloeigrafieke (CFG’s). Gebruik hierdie volgorde:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifiseer die compiler-weergawe.** Probeer eers `BuildInfo` en ingebedde weergawe-strings. As die obfuscator dit verwyder het, vergelyk gedeeltes van die gebundelde Go-runtime met runtime-verwysings vir spesifieke weergawes. In Volexity se toetse was ongeveer `2%` van die runtime genoeg om groot Go-weergawes te onderskei. Beskou dit as ’n empiriese optimalisering, nie as ’n universele drempel nie.<sup>[[13]](#references)</sup>
2. **Bou ooreenstemmende verwysings.** Genereer skoon binaries vir die geïdentifiseerde Go-weergawe, teikenargitektuur en waarskynlike libraries. ’n Ooreenstemmende toolchain verminder CFG-verskille wat deur die compiler gegenereer word.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Vergelyk funksies.** GoGrapher vergelyk funksie-CFG’s en lewer genormaliseerde tellings van `0.0` tot `1.0`. Die basiese-blokpassing is gebaseer op ’n geweegde vergelyking van soortgelyke instruksies. Hoëbetroubaarheids-ooreenstemmings koppel gerandomiseerde funksies aan die skoon implementering. Swakker ooreenstemmings kan steeds ’n pakket of module identifiseer.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Valideer en voer in.** Bevestig voorgestelde name aan die hand van oproepverwantskappe, konstantes, strings en newe-effekte, en voer dan die JSON-verslag in met die GoResolver-inprop vir IDA of Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Installeer die toolchain en voer die gekombineerde onttrekker en grafiekvergelyker uit:<sup>[[10]](#references)</sup>

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

Die verstekdrempel vir betekenisvolle passings is `0.9`. Die `--extract`- en `--graph`-skakelaars kan enige stadium afsonder, terwyl die verstek albei uitvoer omdat die herwonne runtime-metadata en CFG-bewyse mekaar aanvul.<sup>[[10]](#references)</sup> CFG-tellings is heuristies: inlining, build-vlae, argitektuur en verskille in biblioteekweergawes kan die grafiekvorm verander, dus moet onopgeloste funksies behou word eerder as om name met lae vertroue af te dwing.<sup>[[13]](#references)</sup>

### Herwinning van die Go-stringtabel

Go-binêre lêers plaas stringgrepe van elke gekoppelde pakket in een aaneenlopende tabel. Die inskrywings word nie met NUL beëindig nie, en runtime-strukture stel nie die tabel se basisadres of grootte bloot nie. Die samesteller rangskik inskrywings egter eers volgens lengte en daarna alfabeties, oor bedryfstelsels en argitekture heen. Nadat ’n inskrywing gevind is, kan ’n ontleder dus aangrensende inskrywings deurloop en data-kruisverwysings gebruik om stringe aan kode te koppel.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) outomatiseer hierdie werkvloei in IDA Pro en Ghidra. Laat eers outo-analise voltooi, aangesien die inprop op kruisverwysings na datasegmente staatmaak. Die verstekanker is die runtime-string `entersyscall`. Daarna kan dit in enige rigting soek, die herwonne stringe in die databasis definieer en ’n JSON-kartering van stringe na verwysende funksies uitvoer.<sup>[[14]](#references)</sup>

Filter die verslag volgens die pakket van die verwysende funksie om toepassings- of malware-kode van gekoppelde biblioteekgeraas te skei. Hierdie tegniek kan nie letterlike stringe herwin wat deur obfuskasie vernietig is nie, soos Garble se `-literals`-transformasie. Dit kan steeds runtime-stringe organiseer wat nie geobfuseer is nie.<sup>[[14]](#references)[[15]](#references)</sup>

### Herwinning van Go-runtime-tipes

Go sluit runtime-tipe-inligting in wat deur kenmerke soos garbage collection gebruik word. Wanneer build-inligting gestroop is of die disassembler nie hierdie metadata ontleed nie, kan dit lyk asof instruksies willekeurige data-adresse laai, terwyl die teikenstreek ongetipeer bly. Deur die metadata te herwin, word daardie adresse leesbare tipeverwysings, wat dit makliker maak om pakket se vermoëns te verstaan.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) kan simbole onttrek en runtime-tipes ontleed om ’n JSON-verslag te skep. Die huidige CLI gebruik die `resolve`-subopdrag:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Die `-y`/`--types`-opsie aktiveer tipe-ontleding. Voer die verslag in met GoResolver se IDA Pro- of Ghidra-inprop om die herwonne tipes te definieer en hul verwysings in die ontledingsdatabasis toe te pas. In die verslagformaat wat met hierdie funksie bekendgestel is, bly die RTTI-adres- en herwonne-tipes-lede null as `-y` weggelaat word.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver ondersteun PE-, ELF- en Mach-O-monsters vir x86, AMD64, ARM en ARM64, dus geld dieselfde werkvloei vir Go-binêre lêers vanaf Windows, Linux en macOS.<sup>[[10]](#references)</sup>

## Gekompileerde Python

Op hierdie bladsy kan jy uitvind hoe om die Python-kode uit ’n ELF/EXE-binêre lêer met Python te verkry:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

As jy die **binêre lêer** van ’n GBA-speletjie kry, kan jy verskillende nutsprogramme gebruik om dit te **emuleer** en te **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Laai die debug-weergawe af_) - Bevat ’n debugger met ’n koppelvlak
- [**mgba** ](https://mgba.io)- Bevat ’n CLI-debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-inprop
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-inprop

In [**no$gba**](https://problemkaputt.de/gba.htm), onder _**Options --> Emulation Setup --> Controls**_** **, kan jy sien hoe om die Game Boy Advance-**knoppies** te druk.

![no$gba-beheeropstelling wat Game Boy Advance-knoppiekarterings wys](<../../images/image (581).png>)

Wanneer dit gedruk word, het elke **sleutel ’n waarde** waarmee dit geïdentifiseer kan word:

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

Dus, in hierdie tipe program sal die interessante deel **wees hoe die program die gebruikersinvoer hanteer**. By adres **0x4000130** vind jy die algemeen aangetroffe funksie: **KEYINPUT**.

![Ghidra-aansig van 'n GBA-binêre lêer wat na KEYINPUT by adres 0x4000130 verwys](<../../images/image (447).png>)

In die vorige beeld kan jy sien dat die funksie vanaf **FUN_080015a8** geroep word (adresse: _0x080015fa_ en _0x080017ac_).

In daardie funksie, ná enkele init-bewerkings (sonder enige belang):

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

Die laaste if kontroleer of **`uVar4`** in die **laaste sleutels** is en nie die huidige sleutel is nie—ook bekend as om ’n knoppie los te laat (die huidige sleutel word in **`uVar1`** gestoor).

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

In die vorige kode kan jy sien dat ons **uVar1** (die plek waar die **waarde van die ingedrukte knoppie** gestoor word) met sekere waardes vergelyk:

- Eerstens word dit met die **waarde 4** (die **SELECT**-knoppie) vergelyk: In die challenge maak hierdie knoppie die skerm skoon.
- Daarna word die waarde met **8** (die **START**-knoppie) vergelyk; in hierdie challenge kontroleer daardie pad of die ingevoerde kode geldig is.
  - In hierdie geval word die var **`DAT_030000d8`** met 0xf3 vergelyk, en as die waardes ooreenstem, word sekere kode uitgevoer.
- In alle ander gevalle word ’n teller (`DAT_030000d4`) nagegaan en verhoog.\
  Solank die teller kleiner as 8 is, word die waardes van die ingedrukte knoppies by `DAT_030000d8` opgetel.

Dus moes jy in hierdie challenge, met kennis van die knoppiewaardes, **’n kombinasie korter as 8 druk waarvan die som 0xf3 is.**

**Verwysing vir hierdie tutoriaal:** [geargiveerde Nostalgia-challenge-uiteensetting](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [7] [Om AI-ondersteunde reverse engineering te verydel, of ten minste te probeer](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [’n Benadering om beheervloeigrafieke te vergelyk op grond van basiese blokpassing](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver-bewaarplek](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble-obfuskasiemeganisme](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Gebruik van beheervloeigrafiek-ooreenkomste om Golang-binêre lêers outomaties te deobfuskate](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor-bewaarplek](https://github.com/volexity/GoStringExtractor)
- [15] [Go kry dit reg: Opdaterings aan Volexity se Golang-gereedskap](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [REA-ontleding van bestuurde kode](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI- en bewysgids](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
