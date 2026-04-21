# Alati za reversing & osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## ImGui bazirani reversing alati

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

dotPeek je decompiler koji **decompiles i ispituje više formata**, uključujući **libraries** (.dll), **Windows metadata file**s (.winmd) i **executables** (.exe). Nakon decompilation, assembly može da se sačuva kao Visual Studio projekat (.csproj).

Prednost ovde je što, ako je potrebno obnoviti izgubljeni source code iz legacy assembly-ja, ova akcija može da uštedi vreme. Takođe, dotPeek pruža praktičnu navigaciju kroz decompiled code, što ga čini jednim od savršenih alata za **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Sa sveobuhvatnim add-in modelom i API-jem koji proširuje alat da odgovara vašim tačnim potrebama, .NET reflector štedi vreme i pojednostavljuje development. Hajde da pogledamo mnoštvo reverse engineering usluga koje ovaj alat pruža:

- Provides an insight into how the data flows through a library or component
- Provides insight into the implementation and usage of .NET languages and frameworks
- Finds undocumented and unexposed functionality to get more out of the APIs and technologies used.
- Finds dependencies and different assemblies
- Tracks down the exact location of errors in your code, third-party components, and libraries.
- Debugs into the source of all the .NET code you work with.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga imati na bilo kom OS-u (možete ga instalirati direktno iz VSCode, nema potrebe da skidate git. Kliknite na **Extensions** i **search ILSpy**).\
Ako treba da **decompile**, **modify** i **recompile** ponovo, možete da koristite [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegov aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** da promenite nešto unutar funkcije).

### DNSpy Logging

Da biste naterali **DNSpy da upiše neke informacije u fajl**, možete da koristite ovaj snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Da biste debug-ovali kod koristeći DNSpy, potrebno je da:

Prvo, promenite **Assembly attributes** povezane sa **debugging**:

![](<../../images/image (973).png>)

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

![](<../../images/image (314) (1).png>)

Zatim sačuvajte novu datoteku preko _**File >> Save module...**_:

![](<../../images/image (602).png>)

Ovo je neophodno zato što, ako to ne uradite, pri **runtime** će biti primenjene razne **optimisations** na kod i moguće je da tokom debagovanja **break-point nikada ne bude pogođen** ili da neke **variables** ne postoje.

Zatim, ako vaša .NET aplikacija radi pod **IIS**, možete je **restart**ovati sa:
```
iisreset /noforce
```
Zatim, da biste počeli sa debugging-om, trebalo bi da zatvorite sve otvorene fajlove i u okviru **Debug Tab** izaberete **Attach to Process...**:

![](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da se attach-ujete na **IIS server** i kliknite **attach**:

![](<../../images/image (113).png>)

Sada kada debug-ujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na _Debug >> Break All_ a zatim kliknite na _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Kliknite bilo koji modul u **Modules** i izaberite **Open All Modules**:

![](<../../images/image (922).png>)

Desni klik na bilo koji modul u **Assembly Explorer** i kliknite **Sort Assemblies**:

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![](<../../images/image (868).png>)

- Konfigurišite **parameters** izvršavanja tako što ćete uneti **path to the DLL** i funkciju koju želite da pozovete:

![](<../../images/image (704).png>)

Zatim, kada pokrenete debugging, **izvršavanje će biti zaustavljeno kada se svaka DLL učita**, pa kada rundll32 učita vašu DLL, izvršavanje će biti zaustavljeno.

Ali, kako možete doći do koda učitane DLL? Koristeći ovaj metod, ne znam kako.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Primetite da kada je izvršavanje zaustavljeno iz bilo kog razloga u win64dbg možete videti **u kom ste kodu** gledajući u **top of the win64dbg window**:

![](<../../images/image (842).png>)

Zatim, gledajući ovo možete videti kada je izvršavanje zaustavljeno u dll koju želite da debug-ujete.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje gde se važne vrednosti čuvaju u memoriji igre koja je pokrenuta i njihovu izmenu. Više informacija u:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end/reverse engineering alat za GNU Project Debugger (GDB), fokusiran na igre. Međutim, može se koristiti za bilo šta vezano za reverse-engineering

[**Decompiler Explorer**](https://dogbolt.org/) je web front-end za više dekompajlera. Ovaj web servis vam omogućava da uporedite izlaz različitih dekompajlera nad malim izvršnim fajlovima.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) će **allocatovati** **shellcode** unutar prostora memorije, **prikazaće** vam **memory address** na kojoj je shellcode alociran i **zaustaviće** izvršavanje.\
Zatim, potrebno je da se **attach-ujete na debugger** (Ida ili x64dbg) procesu i postavite **breakpoint na naznačenu memory address** i **nastavite** izvršavanje. Na ovaj način ćete debug-ovati shellcode.

Github stranica za releases sadrži zip-ove sa kompajliranim verzijama: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Možete pronaći malo izmenjenu verziju Blobrunner-a na sledećem linku. Da biste je kompajlirali, samo **kreirajte C/C++ project u Visual Studio Code, kopirajte i nalepite kod i build-ujte ga**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)je veoma sličan blobrunner-u. On će **allocatovati** **shellcode** unutar prostora memorije i pokrenuti **večnu petlju**. Zatim je potrebno da **attach-ujete debugger** procesu, **play start wait 2-5 secs and press stop** i naći ćete se unutar **večne petlje**. Pređite na sledeću instrukciju večne petlje, jer će to biti poziv ka shellcode-u, i na kraju ćete se naći kako izvršavate shellcode.

![](<../../images/image (509).png>)

Možete preuzeti kompajliranu verziju [jmp2it sa releases stranice](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI radare-a. Koristeći cutter možete emulirati shellcode i dinamički ga inspektovati.

Imajte na umu da Cutter omogućava da "Open File" i "Open Shellcode". U mom slučaju, kada sam otvorio shellcode kao fajl, dekompajlirao ga je ispravno, ali kada sam ga otvorio kao shellcode, nije:

![](<../../images/image (562).png>)

Da biste pokrenuli emulaciju na mestu koje želite, postavite bp tamo i očigledno će cutter automatski pokrenuti emulaciju odatle:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

Možete videti stack, na primer, unutar hex dump-a:

![](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Trebalo bi da probate [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
On će vam reći stvari kao što su **koje funkcije** shellcode koristi i da li shellcode **dešifruje** sam sebe u memoriji.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg takođe ima grafički launcher gde možeš da izabereš opcije koje želiš i da izvršiš shellcode

![](<../../images/image (258).png>)

Opcija **Create Dump** će dump-ovati finalni shellcode ako se bilo kakva promena dinamički napravi na shellcode-u u memoriji (korisno za preuzimanje decoded shellcode-a). **start offset** može biti koristan za pokretanje shellcode-a na određenom offset-u. Opcija **Debug Shell** je korisna za debugovanje shellcode-a koristeći scDbg terminal (međutim, smatram da su bilo koje od prethodno objašnjenih opcija bolje za ovu svrhu, jer ćeš moći da koristiš Ida ili x64dbg).

### Disassembling using CyberChef

Upload-uj svoj shellcode fajl kao input i koristi sledeći recipe da ga decompile-uješ: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation skriva jednostavne izraze kao što je `x + y` iza formula koje mešaju aritmetičke (`+`, `-`, `*`) i bitwise operatore (`&`, `|`, `^`, `~`, shifts). Važan deo je da su ove identitete obično tačni samo pod **fixed-width modular arithmetic**, tako da carry-ji i overflow-i imaju značaj:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Ako pojednostaviš ovakav tip izraza pomoću generičkog algebra tooling, lako možeš dobiti pogrešan rezultat jer su bit-width semantike ignorisane.

### Practical workflow

1. **Zadrži originalni bit-width** iz lifted code/IR/decompiler output (`8/16/32/64` bits).
2. **Klasifikuj izraz** pre nego što pokušaš da ga pojednostaviš:
- **Linear**: ponderisane sume bitwise atoma
- **Semilinear**: linearno plus konstantne maske kao što je `x & 0xFF`
- **Polynomial**: pojavljuju se proizvodi
- **Mixed**: proizvodi i bitwise logic su isprepletani, često sa ponovljenim subexpressions
3. **Verifikuj svako candidate rewrite** random testing-om ili SMT dokazom. Ako ekvivalencija ne može da se dokaže, zadrži originalni izraz umesto da pogađaš.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktičan MBA simplifier za malware analysis i protected-binary reversing. On klasifikuje izraz i usmerava ga kroz specijalizovane pipelines umesto da primeni jedan generic rewrite pass na sve.

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

- **Linear MBA**: CoBRA evaluira izraz na Boolean ulazima, izvodi signature i paralelno pokreće više metoda oporavka kao što su pattern matching, ANF conversion i coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms se obnavljaju pomoću bit-partitioned reconstruction tako da masked regions ostanu ispravne.
- **Polynomial/Mixed MBA**: proizvodi se razlažu na cores, a ponovljeni subexpressions mogu se izdvojiti u temporaries pre pojednostavljivanja spoljašnjeg relationa.

Primer mixed identity koja se često isplati pokušati da se oporavi:
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
And [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

If you are playing a **CTF, this workaround to find the flag** could be very useful: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

To find the **entry point** search the functions by `::main` like in:

![](<../../images/image (1080).png>)

In this case the binary was called authenticator, so it's pretty obvious that this is the interesting main function.\
Having the **name** of the **functions** being called, search for them on the **Internet** to learn about their **inputs** and **outputs**.

## **Delphi**

For Delphi compiled binaries you can use [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

If you have to reverse a Delphi binary I would suggest you to use the IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Just press **ATL+f7** (import python plugin in IDA) and select the python plugin.

This plugin will execute the binary and resolve function names dynamically at the start of the debugging. After starting the debugging press again the Start button (the green one or f9) and a breakpoint will hit in the beginning of the real code.

It is also very interesting because if you press a button in the graphic application the debugger will stop in the function executed by that bottom.

## Golang

If you have to reverse a Golang binary I would suggest you to use the IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Just press **ATL+f7** (import python plugin in IDA) and select the python plugin.

This will resolve the names of the functions.

## Compiled Python

In this page you can find how to get the python code from an ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

If you get the **binary** of a GBA game you can use different tools to **emulate** and **debug** it:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Contains a debugger with interface
- [**mgba** ](https://mgba.io)- Contains a CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** you can see how to press the Game Boy Advance **buttons**

![](<../../images/image (581).png>)

When pressed, each **key has a value** to identify it:
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
Dakle, u ovoj vrsti programa, zanimljiv deo biće **kako program tretira korisnički unos**. Na adresi **0x4000130** pronaći ćete često prisutnu funkciju: **KEYINPUT**.

![](<../../images/image (447).png>)

Na prethodnoj slici možete videti da se funkcija poziva iz **FUN_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekih init operacija (bez ikakvog značaja):
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
Pronađen je ovaj code:
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
Poslednji `if` proverava da li je **`uVar4`** u **last Keys** i da nije trenutni key, što se takođe naziva otpuštanje dugmeta (trenutni key je sačuvan u **`uVar1`**).
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
U prethodnom kodu možete videti da poredimo **uVar1** (mesto gde je **vrednost pritisnutog dugmeta** ) sa nekim vrednostima:

- Prvo, poredi se sa **vrednošću 4** (**SELECT** dugme): U izazovu ovo dugme briše ekran
- Zatim, poredi se sa **vrednošću 8** (**START** dugme): U izazovu ovo proverava da li je kod validan za dobijanje flag-a.
- U ovom slučaju, var **`DAT_030000d8`** se poredi sa 0xf3 i ako je vrednost ista, izvršava se neki kod.
- U svim drugim slučajevima, proverava se neki cont (**`DAT_030000d4`**). To je cont zato što se povećava za 1 odmah nakon ulaska u kod.\
**A**ko je manji od 8, radi se nešto što uključuje **dodavanje** vrednosti u **`DAT_030000d8`** (u osnovi, dodaju se vrednosti pritisnutih tastera u ovu varijablu sve dok je cont manji od 8).

Dakle, u ovom izazovu, znajući vrednosti dugmadi, trebalo je da **pritisnete kombinaciju dužine manje od 8 čiji zbir daje 0xf3.**

**Reference for this tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

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

{{#include ../../banners/hacktricks-training.md}}
