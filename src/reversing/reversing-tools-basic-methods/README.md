# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui-gebaseerde omkeerhulpmiddels

Sagtemak:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Aanlyn:

- Gebruik [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) om te **decompile** van wasm (binêr) na wat (duidelike teks)
- Gebruik [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) om te **compile** van wat na wasm
- jy kan ook probeer om [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) te gebruik om te decompile

Sagtemak:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is 'n decompiler wat **decompileer en ondersoek verskeie formate**, insluitend **biblioteke** (.dll), **Windows metadata lêers** (.winmd), en **uitvoerbare lêers** (.exe). Sodra dit gedecompileer is, kan 'n samestelling as 'n Visual Studio-projek (.csproj) gestoor word.

Die voordeel hier is dat as 'n verlore bronkode herstel moet word uit 'n erfenis-samestelling, kan hierdie aksie tyd bespaar. Verder bied dotPeek handige navigasie deur die gedecompileerde kode, wat dit een van die perfekte hulpmiddels maak vir **Xamarin-algoritme-analise.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Met 'n omvattende byvoegingmodel en 'n API wat die hulpmiddel uitbrei om aan jou presiese behoeftes te voldoen, bespaar .NET reflector tyd en vereenvoudig ontwikkeling. Kom ons kyk na die oorvloed van omgekeerde ingenieursdienste wat hierdie hulpmiddel bied:

- Bied insig in hoe die data deur 'n biblioteek of komponent vloei
- Bied insig in die implementering en gebruik van .NET tale en raamwerke
- Vind ongedokumenteerde en nie-blootgestelde funksionaliteit om meer uit die API's en tegnologieë te kry.
- Vind afhanklikhede en verskillende samestellings
- Spoor die presiese ligging van foute in jou kode, derdeparty-komponente, en biblioteke op.
- Debug in die bron van al die .NET kode waarmee jy werk.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-inprop vir Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Jy kan dit in enige OS hê (jy kan dit direk van VSCode installeer, geen behoefte om die git af te laai nie. Klik op **Extensions** en **soek ILSpy**).\
As jy wil **decompile**, **wysig** en **hercompile** weer kan jy [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) of 'n aktief onderhandeerde fork daarvan, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) gebruik. (**Regsklik -> Wysig Metode** om iets binne 'n funksie te verander).

### DNSpy Logging

Om te maak dat **DNSpy 'n paar inligting in 'n lêer log**, kan jy hierdie snit gebruik:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Foutopsporing

Om kode met DNSpy te foutopspoor, moet jy:

Eerstens, verander die **Assembly eienskappe** wat verband hou met **foutopsporing**:

![](<../../images/image (973).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Na:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
En klik op **compile**:

![](<../../images/image (314) (1).png>)

Stoor dan die nuwe lêer via _**File >> Save module...**_:

![](<../../images/image (602).png>)

Dit is nodig omdat as jy dit nie doen nie, verskeie **optimisations** tydens **runtime** op die kode toegepas sal word en dit moontlik is dat terwyl jy debugg, 'n **break-point nooit bereik** word of sommige **variabeles nie bestaan** nie.

As jou .NET-toepassing deur **IIS** **run** word, kan jy dit **herbegin** met:
```
iisreset /noforce
```
Dan, om te begin debugg, moet jy al die geopen lêers sluit en binne die **Debug Tab** **Attach to Process...** kies:

![](<../../images/image (318).png>)

Kies dan **w3wp.exe** om aan die **IIS-server** te koppel en klik op **attach**:

![](<../../images/image (113).png>)

Nou dat ons die proses debugg, is dit tyd om dit te stop en al die modules te laai. Klik eers op _Debug >> Break All_ en klik dan op _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Klik op enige module in **Modules** en kies **Open All Modules**:

![](<../../images/image (922).png>)

Regsklik op enige module in **Assembly Explorer** en klik op **Sort Assemblies**:

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Gebruik IDA

- **Laai rundll32** (64bits in C:\Windows\System32\rundll32.exe en 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Kies **Windbg** debugg
- Kies "**Suspend on library load/unload**"

![](<../../images/image (868).png>)

- Konfigureer die **parameters** van die uitvoering deur die **pad na die DLL** en die funksie wat jy wil aanroep in te stel:

![](<../../images/image (704).png>)

Dan, wanneer jy begin debugg, **sal die uitvoering gestop word wanneer elke DLL gelaai word**, dan, wanneer rundll32 jou DLL laai, sal die uitvoering gestop word.

Maar, hoe kan jy by die kode van die DLL wat gelaai is, kom? Met hierdie metode, weet ek nie hoe nie.

### Gebruik x64dbg/x32dbg

- **Laai rundll32** (64bits in C:\Windows\System32\rundll32.exe en 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Verander die Command Line** ( _File --> Change Command Line_ ) en stel die pad van die dll en die funksie wat jy wil aanroep, byvoorbeeld: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Verander _Options --> Settings_ en kies "**DLL Entry**".
- Dan **begin die uitvoering**, die debugg sal by elke dll main stop, op 'n sekere punt sal jy **stop in die dll Entry van jou dll**. Van daar af, soek net die punte waar jy 'n breakpoint wil plaas.

Let daarop dat wanneer die uitvoering om enige rede in win64dbg gestop word, jy kan sien **in watter kode jy is** deur na die **boonste deel van die win64dbg venster** te kyk:

![](<../../images/image (842).png>)

Dan, deur na hierdie te kyk, kan jy sien wanneer die uitvoering in die dll wat jy wil debugg, gestop is.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes binne die geheue van 'n lopende speletjie gestoor word en om dit te verander. Meer info in:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is 'n front-end/omgekeerde ingenieursgereedskap vir die GNU Project Debugger (GDB), gefokus op speletjies. Dit kan egter vir enige omgekeerde ingenieurswerk verwante goed gebruik word.

[**Decompiler Explorer**](https://dogbolt.org/) is 'n web front-end vir 'n aantal decompilers. Hierdie webdiens laat jou toe om die uitvoer van verskillende decompilers op klein uitvoerbare lêers te vergelyk.

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Debugging 'n shellcode met blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) sal **toewys** die **shellcode** binne 'n geheue ruimte, sal jou die **geheue adres** aandui waar die shellcode toegewy is en sal die uitvoering **stop**.\
Dan moet jy 'n **debugger** (Ida of x64dbg) aan die proses koppel en 'n **breakpoint op die aangeduide geheue adres** plaas en die uitvoering **herbegin**. Op hierdie manier sal jy die shellcode debugg.

Die releases github bladsy bevat zips wat die gecompileerde releases bevat: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Jy kan 'n effens gewysigde weergawe van Blobrunner in die volgende skakel vind. Om dit te compileer, moet jy net **'n C/C++ projek in Visual Studio Code skep, die kode kopieer en plak en dit bou**.

{{#ref}}
blobrunner.md
{{#endref}}

### Debugging 'n shellcode met jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) is baie soortgelyk aan blobrunner. Dit sal **toewys** die **shellcode** binne 'n geheue ruimte, en 'n **ewige lus** begin. Jy moet dan die **debugger** aan die proses koppel, **speel begin wag 2-5 sekondes en druk stop** en jy sal jouself binne die **ewige lus** vind. Spring na die volgende instruksie van die ewige lus, aangesien dit 'n oproep na die shellcode sal wees, en uiteindelik sal jy jouself vind wat die shellcode uitvoer.

![](<../../images/image (509).png>)

Jy kan 'n gecompileerde weergawe van [jmp2it binne die releases bladsy aflaai](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode met Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is die GUI van radare. Met cutter kan jy die shellcode emuleer en dit dinamies inspekteer.

Let daarop dat Cutter jou toelaat om "Open File" en "Open Shellcode" te kies. In my geval, toe ek die shellcode as 'n lêer oopgemaak het, het dit dit korrek decompiled, maar toe ek dit as 'n shellcode oopgemaak het, het dit nie:

![](<../../images/image (562).png>)

Om die emulering te begin op die plek waar jy wil, stel 'n bp daar in en blykbaar sal cutter outomaties die emulering vanaf daar begin:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

Jy kan die stapel sien, byvoorbeeld, binne 'n hex dump:

![](<../../images/image (186).png>)

### Deobfuscating shellcode en die uitgevoerde funksies kry

Jy moet probeer [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Dit sal jou dinge vertel soos **watter funksies** die shellcode gebruik en of die shellcode **homself decodeer** in geheue.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg het ook 'n grafiese laaier waar jy die opsies kan kies wat jy wil en die shellcode kan uitvoer.

![](<../../images/image (258).png>)

Die **Create Dump** opsie sal die finale shellcode dump as enige verandering aan die shellcode dinamies in geheue gemaak word (nuttig om die gedecodeerde shellcode af te laai). Die **start offset** kan nuttig wees om die shellcode by 'n spesifieke offset te begin. Die **Debug Shell** opsie is nuttig om die shellcode te debug met behulp van die scDbg terminal (ek vind egter enige van die opsies wat voorheen verduidelik is beter vir hierdie saak, aangesien jy Ida of x64dbg kan gebruik).

### Disassembling using CyberChef

Laai jou shellcode-lêer op as invoer en gebruik die volgende resep om dit te dekompileer: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Hierdie obfuscator **wysig al die instruksies vir `mov`** (ja, regtig cool). Dit gebruik ook onderbrekings om uitvoeringsvloei te verander. Vir meer inligting oor hoe dit werk:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

As jy gelukkig is, sal [demovfuscator](https://github.com/kirschju/demovfuscator) die binêre deobfuskeer. Dit het verskeie afhanklikhede.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
En [installeer keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

As jy 'n **CTF speel, kan hierdie omweg om die vlag te vind** baie nuttig wees: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Om die **toegangspunt** te vind, soek die funksies deur `::main` soos in:

![](<../../images/image (1080).png>)

In hierdie geval was die binêre genaamd authenticator, so dit is redelik voor die hand liggend dat dit die interessante hooffunksie is.\
Met die **naam** van die **funksies** wat aangeroep word, soek daarna op die **Internet** om meer te leer oor hul **insette** en **uitsette**.

## **Delphi**

Vir Delphi gecompileerde binêre kan jy gebruik maak van [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

As jy 'n Delphi binêre moet omkeer, sou ek jou aanbeveel om die IDA-inprop [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) te gebruik.

Druk net **ATL+f7** (import python plugin in IDA) en kies die python plugin.

Hierdie inprop sal die binêre uitvoer en funksiename dinamies aan die begin van die debuggery oplos. Nadat jy die debuggery begin het, druk weer die Begin-knoppie (die groen een of f9) en 'n breekpunt sal aan die begin van die werklike kode tref.

Dit is ook baie interessant omdat as jy 'n knoppie in die grafiese toepassing druk, die debugger in die funksie wat deur daardie knoppie uitgevoer word, sal stop.

## Golang

As jy 'n Golang binêre moet omkeer, sou ek jou aanbeveel om die IDA-inprop [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) te gebruik.

Druk net **ATL+f7** (import python plugin in IDA) en kies die python plugin.

Dit sal die name van die funksies oplos.

## Gecompileerde Python

Op hierdie bladsy kan jy vind hoe om die python kode van 'n ELF/EXE python gecompileerde binêre te kry:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

As jy die **binêre** van 'n GBA-speletjie kry, kan jy verskillende gereedskap gebruik om dit te **emuleer** en te **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Laai die debug weergawe af_) - Bevat 'n debugger met 'n koppelvlak
- [**mgba** ](https://mgba.io)- Bevat 'n CLI-debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-inprop
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-inprop

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Opsies --> Emulasie-opstelling --> Beheer**_\*\* \*\* kan jy sien hoe om die Game Boy Advance **knoppies** te druk.

![](<../../images/image (581).png>)

Wanneer gedruk, het elke **sleutel 'n waarde** om dit te identifiseer:
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
So, in hierdie tipe program, die interessante deel sal wees **hoe die program die gebruiker invoer hanteer**. In die adres **0x4000130** sal jy die algemeen aangetrefde funksie vind: **KEYINPUT**.

![](<../../images/image (447).png>)

In die vorige beeld kan jy sien dat die funksie aangeroep word vanaf **FUN_080015a8** (adresse: _0x080015fa_ en _0x080017ac_).

In daardie funksie, na 'n paar inisialisasie operasies (sonder enige belangrikheid):
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
Dit is gevind hierdie kode:
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
Die laaste if kyk of **`uVar4`** in die **laaste Sleutels** is en nie die huidige sleutel is nie, wat ook genoem word om 'n knoppie los te laat (die huidige sleutel word in **`uVar1`** gestoor).
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
In die vorige kode kan jy sien dat ons **uVar1** (die plek waar die **waarde van die gedrukte knoppie** is) met 'n paar waardes vergelyk:

- Eerstens, dit word vergelyk met die **waarde 4** (**SELECT** knoppie): In die uitdaging maak hierdie knoppie die skerm skoon.
- Dan, dit word vergelyk met die **waarde 8** (**START** knoppie): In die uitdaging kontroleer dit of die kode geldig is om die vlag te kry.
- In hierdie geval word die var **`DAT_030000d8`** met 0xf3 vergelyk en as die waarde dieselfde is, word 'n paar kode uitgevoer.
- In enige ander gevalle, word 'n cont (`DAT_030000d4`) nagegaan. Dit is 'n cont omdat dit 1 byvoeg onmiddellik nadat dit in die kode ingaan.\
**As** dit minder as 8 is, word iets wat **byvoeg** waardes aan \*\*`DAT_030000d8` \*\* doen (basies voeg dit die waardes van die knoppies wat in hierdie veranderlike gedruk is by solank die cont minder as 8 is).

So, in hierdie uitdaging, om die waardes van die knoppies te ken, moes jy **'n kombinasie druk met 'n lengte kleiner as 8 wat die resultaat toevoeging 0xf3 is.**

**Verwysing vir hierdie tutoriaal:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Kursusse

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binarie deobfuscation)

{{#include ../../banners/hacktricks-training.md}}
