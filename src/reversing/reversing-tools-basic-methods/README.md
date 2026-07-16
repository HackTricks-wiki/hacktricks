# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui Based Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) to **decompile** from wasm (binary) to wat (clear text)
- Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) to **compile** from wat to wasm
- you can also try to use [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) to decompile

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je decompiler koji **decompiles and examines multiple formats**, uključujući **biblioteke** (.dll), **Windows metadata file**s (.winmd) i **izvršne fajlove** (.exe). Kada se dekompajlira, assembly može da se sačuva kao Visual Studio projekat (.csproj).

Prednost ovde je što, ako je potrebno vratiti izgubljeni source code iz legacy assembly-ja, ova radnja može da uštedi vreme. Takođe, dotPeek pruža praktičnu navigaciju kroz dekompajlirani kod, što ga čini jednim od savršenih alata za **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Sa sveobuhvatnim add-in modelom i API-jem koji proširuje alat da odgovara tvojim tačnim potrebama, .NET reflector štedi vreme i pojednostavljuje development. Pogledajmo mnoštvo reverse engineering usluga koje ovaj alat pruža:

- Pruža uvid u to kako se data flows kroz library ili component
- Pruža uvid u implementaciju i upotrebu .NET jezika i frameworks
- Pronalazi undocumented i unexposed funkcionalnost da bi se izvuklo više iz APIs i tehnologija koje se koriste.
- Pronalazi dependencies i različite assemblies
- Prati tačnu lokaciju grešaka u tvom kodu, third-party components i libraries.
- Debugs into the source of all the .NET code you work with.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možeš ga imati na bilo kom OS-u (možeš ga instalirati direktno iz VSCode-a, nema potrebe da skidaš git. Klikni na **Extensions** i **search ILSpy**).\
Ako treba da **decompile**, **modify** i ponovo **recompile** možeš da koristiš [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegov aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** da promeniš nešto unutar funkcije).

### DNSpy Logging

Da bi **DNSpy log some information in a file**, možeš da koristiš ovaj snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Da biste debugovali kod koristeći DNSpy, potrebno je da:

Prvo, promenite **Assembly attributes** koji se odnose na **debugging**:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

Od:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Za:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
I kliknite na **compile**:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Zatim sačuvajte novi fajl preko _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Ovo je neophodno zato što će se, ako ovo ne uradite, tokom **runtime** primeniti nekoliko **optimizacija** na kod i moguće je da tokom debagovanja **break-point nikada neće biti pogođen** ili da neke **promenljive ne postoje**.

Zatim, ako vaša .NET aplikacija radi preko **IIS** možete je **restartovati** pomoću:
```
iisreset /noforce
```
Then, in order to start debugging you should close all the opened files and inside the **Debug Tab** select **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Then, in order to start debugging you should close all the opened files and inside the Debug Tab select Attach to Process](<../../images/image (318).png>)

Then select **w3wp.exe** to attach to the **IIS server** and click **attach**:

![DNSpy Logging - DNSpy Debugging: Then select w3wp.exe to attach to the IIS server and click attach](<../../images/image (113).png>)

Now that we are debugging the process, it's time to stop it and load all the modules. First click on _Debug >> Break All_ and then click on _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (834).png>)

Click any module on **Modules** and select **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Click any module on Modules and select Open All Modules](<../../images/image (922).png>)

Right click any module in **Assembly Explorer** and click **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Right click any module in Assembly Explorer and click Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Select " Suspend on library load/unload "](<../../images/image (868).png>)

- Configure the **parameters** of the execution putting the **path to the DLL** and the function that you want to call:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

Then, when you start debugging **the execution will be stopped when each DLL is loaded**, then, when rundll32 load your DLL the execution will be stopped.

But, how can you get to the code of the DLL that was lodaded? Using this method, I don't know how.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Notice that when the execution is stopped by any reason in win64dbg you can see **in which code you are** looking in the **top of the win64dbg window**:

![Using IDA - Using x64dbg/x32dbg: Notice that when the execution is stopped by any reason in win64dbg you can see in which code you are looking in the top of the win64dbg window](<../../images/image (842).png>)

Then, looking to this ca see when the execution was stopped in the dll you want to debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is a useful program to find where important values are saved inside the memory of a running game and change them. More info in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is a front-end/reverse engineering tool for the GNU Project Debugger (GDB), focused on games. However, it can be used for any reverse-engineering related stuff

[**Decompiler Explorer**](https://dogbolt.org/) is a web front-end to a number of decompilers. This web service lets you compare the output of different decompilers on small executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) will **allocate** the **shellcode** inside a space of memory, will **indicate** you the **memory address** were the shellcode was allocated and will **stop** the execution.\
Then, you need to **attach a debugger** (Ida or x64dbg) to the process and put a **breakpoint the indicated memory address** and **resume** the execution. This way you will be debugging the shellcode.

The releases github page contains zips containing the compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
You can find a slightly modified version of Blobrunner in the following link. In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)is very similar to blobrunner. It will **allocate** the **shellcode** inside a space of memory, and start an **eternal loop**. You then need to **attach the debugger** to the process, **play start wait 2-5 secs and press stop** and you will find yourself inside the **eternal loop**. Jump to the next instruction of the eternal loop as it will be a call to the shellcode, and finally you will find yourself executing the shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it is very similar to blobrunner. It will allocate the shellcode inside a space of memory, and start an...](<../../images/image (509).png>)

You can download a compiled version of [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is the GUI of radare. Using cutter you can emulate the shellcode and inspect it dynamically.

Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it decompiled it correctly, but when I opened it as a shellcode it didn't:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it...](<../../images/image (562).png>)

In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically start the emulation from there:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (387).png>)

You can see the stack for example inside a hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: You can see the stack for example inside a hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

You should try [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
It will tell you things like **which functions** is the shellcode using and if the shellcode is **decoding** itself in memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg takođe ima grafički launcher gde možete da izaberete opcije koje želite i izvršite shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

Opcija **Create Dump** će dump-ovati finalni shellcode ako se bilo kakva promena dinamički izvrši nad shellcode-om u memoriji (korisno za preuzimanje dekodiranog shellcode-a). Opcija **start offset** može biti korisna za pokretanje shellcode-a na određenom offset-u. Opcija **Debug Shell** je korisna za debugovanje shellcode-a koristeći scDbg terminal (međutim, smatram da su bilo koje od prethodno objašnjenih opcija bolje za ovu svrhu jer ćete moći da koristite Ida ili x64dbg).

### Disassembling using CyberChef

Uploadujte vaš shellcode fajl kao input i koristite sledeći recipe da ga dekompajlirate: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation skriva jednostavne izraze kao što je `x + y` iza formula koje mešaju aritmetičke (`+`, `-`, `*`) i bitovne operatore (`&`, `|`, `^`, `~`, shift-ove). Važan deo je da su ove identitete obično tačne samo pod **modularnom aritmetikom fiksne širine**, pa su carry i overflow bitni:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Ako pojednostaviš ovakav tip izraza pomoću generičkih algebarskih alata, lako možeš dobiti pogrešan rezultat jer su semantike širine bita ignorisane.

### Praktičan workflow

1. **Zadrži originalnu širinu bita** iz podignutog code/IR/decompiler izlaza (`8/16/32/64` bits).
2. **Klasifikuj izraz** pre nego što pokušaš da ga pojednostaviš:
- **Linear**: ponderisani zbirovi bitwise atoma
- **Semilinear**: linearno plus konstantne maske kao što su `x & 0xFF`
- **Polynomial**: pojavljuju se proizvodi
- **Mixed**: proizvodi i bitwise logic su isprepletani, često sa ponovljenim podizrazaima
3. **Verifikuj svaku kandidatsku rewrite** random testiranjem ili SMT dokazom. Ako ekvivalencija ne može da se dokaže, zadrži originalni izraz umesto da nagađaš.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktičan MBA simplifier za malware analysis i protected-binary reversing. Klasifikuje izraz i prosleđuje ga kroz specijalizovane pipeline-ove umesto da primeni jedan generički rewrite pass na sve.

Quick usage:
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
Korisni slučajevi:

- **Linear MBA**: CoBRA evaluira izraz na Boolean ulazima, izvodi signature, i pokreće više metoda oporavka kao što su pattern matching, ANF conversion, i coefficient interpolation.
- **Semilinear MBA**: konstantno maskirani atoms se ponovo grade pomoću bit-partitioned reconstruction tako da maskirane oblasti ostanu ispravne.
- **Polynomial/Mixed MBA**: products se razlažu na cores i ponovljeni subexpressions mogu biti izdignuti u temporaries pre pojednostavljivanja spoljne relacije.

Primer mixed identity koja je često vredna pokušaja oporavka:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Ovo može da se svede na:
```c
x * y
```
### Reversing notes

- Prefer running CoBRA on **lifted IR expressions** or decompiler output after you isolated the exact computation.
- Use `--bitwidth` explicitly when the expression came from masked arithmetic or narrow registers.
- If you need a stronger proof step, check the local Z3 notes here:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA also ships as an **LLVM pass plugin** (`libCobraPass.so`), which is useful when you want to normalize MBA-heavy LLVM IR before later analysis passes.
- Unsupported carry-sensitive mixed-domain residuals should be treated as a signal to keep the original expression and reason about the carry path manually.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

This obfuscator **modifies all the instructions for `mov`**(yeah, really cool). It also uses interruptions to change executions flows. For more information about how does it works:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

If you are lucky [demovfuscator](https://github.com/kirschju/demovfuscator) will deofuscate the binary. It has several dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
I [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

If you are playing a **CTF, this workaround to find the flag** could be very useful: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **entry point** pretražite funkcije po `::main` kao u:

![Movfuscator - Rust: To find the entry point search the functions by ::main like in](<../../images/image (1080).png>)

U ovom slučaju binarni fajl se zvao authenticator, pa je prilično očigledno da je ovo zanimljiva main funkcija.\
Pošto znate **name** od **functions** koje se pozivaju, pretražite ih na **Internetu** da biste saznali njihove **inputs** i **outputs**.

### Recovering Rust strings from ELF firmware

U **Rust ELF** binarnim fajlovima, mnogi statički stringovi nisu referencirani kao C-style NUL-terminated pokazivači. Uobičajen `rustc` raspored je **pointer/length tuple** unutar **`.data.rel.ro`** koji pokazuje na pravi string blob smešten u **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
To znači da `strings` ili podrazumevana Ghidra analiza mogu spojiti susedne stringove ili potpuno propustiti cross-references.

Brzi workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Dobijte virtuelnu adresu i veličinu **`.rodata`**.
2. Enumerišite **`.data.rel.ro`** jednu reč u isto vreme.
3. Tretirajte svaku vrednost unutar adresnog opsega `.rodata` kao kandidata za pokazivač na string.
4. Tretirajte sledeću reč kao kandidata za dužinu.
5. Primeni sanity filtere (na primer, zadržite dužine između **4** i **100** bajtova).
6. Pročitajte tačno `length` bajtova iz `.rodata` umesto da skenirate do `0x00`.

Minimal extractor logic:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Ovo je posebno korisno pri firmware reversing jer recovered Rust strings često otkrivaju **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, i auth-related logic**.

Ako Ghidra propusti te stringove, pokreni custom script/plugin koji primenjuje istu heuristiku i kreira string data na referenciranim `.rodata` offsetima. Objavljeni `rust-strings` i `RustStrings.py` alati od Pen Test Partners su dobri reference za prilagođavanje ideje drugim **word sizes, endianness, i section layouts**.

## **Delphi**

Za Delphi compiled binaries možeš koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako treba da reverse-uješ Delphi binary, preporučio bih ti da koristiš IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Samo pritisni **ATL+f7** (import python plugin in IDA) i izaberi python plugin.

Ovaj plugin će izvršiti binary i dinamički resolve-ovati function names na početku debugginga. Nakon pokretanja debugginga ponovo pritisni Start dugme (zeleno ili f9) i breakpoint će se aktivirati na početku pravog code-a.

Takođe je veoma zanimljivo jer ako pritisneš dugme u grafičkoj aplikaciji, debugger će se zaustaviti u funkciji koja se izvršava pritiskom tog dugmeta.

## Golang

Ako treba da reverse-uješ Golang binary, preporučio bih ti da koristiš IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Samo pritisni **ATL+f7** (import python plugin in IDA) i izaberi python plugin.

Ovo će resolve-ovati imena funkcija.

## Compiled Python

Na ovoj stranici možeš pronaći kako da dobiješ python code iz ELF/EXE python compiled binary-ja:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Ako dobiješ **binary** GBA igre, možeš koristiti različite alate da je **emulate** i **debug**-uješ:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmi debug verziju_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

U [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_** ** možeš videti kako da pritisneš Game Boy Advance **buttons**

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Kada se pritisnu, svaki **key ima vrednost** da ga identifikuje:
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
Dakle, u ovom tipu programa, zanimljiv deo će biti **kako program obrađuje korisnički unos**. Na adresi **0x4000130** naći ćete često prisutnu funkciju: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

U prethodnoj slici možete videti da se funkcija poziva iz **FUN_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekih inicijalizacionih operacija (bez ikakvog značaja):
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
Pronađen je ovaj kod:
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
Poslednji `if` proverava da li je **`uVar4`** u **last Keys** i nije trenutni key, što se takođe zove puštanje dugmeta (trenutni key je sačuvan u **`uVar1`**).
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
U prethodnom kodu možeš da vidiš da poređujemo **uVar1** (mesto gde je **vrednost pritisnutog dugmeta**) sa nekim vrednostima:

- Prvo se poredi sa **vrednošću 4** (**SELECT** dugme): U izazovu ovo dugme čisti ekran
- Zatim se poredi sa **vrednošću 8** (**START** dugme): U izazovu ovo proverava da li je kod validan da bi se dobila zastavica.
- U ovom slučaju var **`DAT_030000d8`** se poredi sa 0xf3 i ako je vrednost ista izvršava se neki kod.
- U svim drugim slučajevima, proverava se neki cont (**`DAT_030000d4`**). To je cont jer se dodaje 1 odmah nakon ulaska u kod.\
**A**ko je manji od 8, radi se nešto što uključuje **sabiranje** vrednosti u **`DAT_030000d8`** (u osnovi, sabiraju se vrednosti pritisnutih tastera u ovu varijablu dokle god je cont manji od 8).

Dakle, u ovom izazovu, znajući vrednosti dugmadi, trebalo je da **pritisneš kombinaciju dužine manje od 8 tako da zbir bude 0xf3.**

**Reference za ovaj tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)

{{#include ../../banners/hacktricks-training.md}}
