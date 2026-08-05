# Reversing alati i osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## Reversing alati zasnovani na ImGui

Softver:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) za **decompile** iz wasm (binarni) u wat (čitljiv tekst)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) za **compile** iz wat u wasm
- takođe možete pokušati da koristite [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) za decompile

Softver:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je decompiler koji **decompiluje i ispituje više formata**, uključujući **biblioteke** (.dll), **Windows metadata fajlove** (.winmd) i **izvršne fajlove** (.exe). Nakon decompilation-a, assembly se može sačuvati kao Visual Studio projekat (.csproj).

Prednost je u tome što, ako je potrebno obnoviti izgubljeni source code iz legacy assembly-ja, ova radnja može uštedeti vreme. Pored toga, dotPeek omogućava praktičnu navigaciju kroz decompilovani code, što ga čini jednim od savršenih alata za **analizu Xamarin algoritama.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Sa sveobuhvatnim add-in modelom i API-jem koji proširuje alat kako bi odgovarao vašim potrebama, .NET reflector štedi vreme i pojednostavljuje development. Pogledajmo mnoštvo usluga reverse engineering-a koje ovaj alat pruža:

- Omogućava uvid u to kako podaci prolaze kroz biblioteku ili komponentu
- Omogućava uvid u implementaciju i upotrebu .NET jezika i framework-a
- Pronalazi nedokumentovanu i neizloženu funkcionalnost kako bi se bolje iskoristili korišćeni API-ji i tehnologije.
- Pronalazi dependencies i različite assembly-je
- Pronalazi tačnu lokaciju grešaka u vašem code-u, third-party komponentama i bibliotekama.
- Omogućava debug source code-a celokupnog .NET code-a sa kojim radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga direktno instalirati iz VSCode-a, nema potrebe da preuzimate git. Kliknite na **Extensions** i **pretražite ILSpy**).\
Ako treba da **decompile**, **modifikujete** i ponovo **compile-ujete**, možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegov aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Desni klik -> Modify Method** da biste promenili nešto unutar funkcije).

### DNSpy Logging

Da biste omogućili da **DNSpy loguje određene informacije u fajl**, možete koristiti sledeći snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Da biste otklanjali greške u kodu koristeći DNSpy, potrebno je da:

Prvo promenite **Assembly attributes** povezane sa **debugging-om**:

![DNSpy Logging - DNSpy Debugging: Prvo promenite Assembly attributes povezane sa debugging-om](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: Kliknite na compile](<../../images/image (314) (1).png>)

Zatim sačuvajte novu datoteku putem _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Zatim sačuvajte novu datoteku putem File Save module](<../../images/image (602).png>)

Ovo je neophodno zato što će, ako to ne uradite, u **runtime**-u na kod biti primenjeno nekoliko **optimizacija**, pa je moguće da se tokom debugging-a **break-point nikada ne aktivira** ili da neke **promenljive ne postoje**.

Zatim, ako se vaša .NET aplikacija **pokreće** putem **IIS**-a, možete je **restartovati** pomoću:
```
iisreset /noforce
```
Zatim, da biste započeli debugging, zatvorite sve otvorene fajlove i unutar **Debug Tab** izaberite **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste započeli debugging, zatvorite sve otvorene fajlove i unutar Debug Tab izaberite Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste ga prikačili na **IIS server** i kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste ga prikačili na IIS server i kliknite na attach](<../../images/image (113).png>)

Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na _Debug >> Break All_, a zatim na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u **Modules** i izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u Modules i izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom na bilo koji modul u **Assembly Explorer** i kliknite na **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom na bilo koji modul u Assembly Explorer i kliknite na Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Izaberite **Windbg** debugger
- Izaberite "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Konfigurišite **parameters** izvršavanja tako što ćete uneti **path to the DLL** i funkciju koju želite da pozovete:

![Debugging DLLs - Using IDA: Konfigurišite parameters izvršavanja tako što ćete uneti path to the DLL i funkciju koju želite da pozovete](<../../images/image (704).png>)

Zatim, kada započnete debugging, **izvršavanje će biti zaustavljeno svaki put kada se učita DLL**, a kada rundll32 učita vaš DLL, izvršavanje će biti zaustavljeno.

Ali kako možete doći do koda učitanog DLL-a? Koristeći ovaj metod, ne znam kako.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) i postavite putanju do dll-a i funkciju koju želite da pozovete, na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Promenite _Options --> Settings_ i izaberite "**DLL Entry**".
- Zatim **start the execution**, debugger će se zaustaviti na svakom dll main-u; u jednom trenutku ćete se **zaustaviti u dll Entry vašeg dll-a**. Od tog mesta samo pronađite tačke na koje želite da postavite breakpoint.

Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg, možete videti **u kom kodu se nalazite** gledajući **vrh prozora win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg, možete videti u kom kodu se nalazite gledajući vrh prozora win64dbg](<../../images/image (842).png>)

Zatim, gledajući ovo, možete videti kada je izvršavanje zaustavljeno u dll-u koji želite da debugujete.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje mesta na kojima se važne vrednosti čuvaju u memoriji pokrenute igre i njihovu izmenu. Više informacija na:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end/reverse engineering alat za GNU Project Debugger (GDB), fokusiran na igre. Međutim, može se koristiti za bilo šta povezano sa reverse engineering-om.

[**Decompiler Explorer**](https://dogbolt.org/) je web front-end za više decompiler-a. Ovaj web servis vam omogućava da uporedite izlaz različitih decompiler-a na malim executable fajlovima.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) će **allocate** **shellcode** unutar memorijskog prostora, **indicate** vam **memory address** na kojoj je shellcode alociran i **stop** izvršavanje.\
Zatim je potrebno da **attach a debugger** (Ida ili x64dbg) na proces, postavite **breakpoint na navedenu memory address** i **resume** izvršavanje. Na ovaj način ćete debugovati shellcode.

Github stranica sa releases sadrži zip arhive sa kompajliranim releases verzijama: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blago izmenjenu verziju Blobrunner-a možete pronaći na sledećem linku. Da biste je kompajlirali, samo **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je veoma sličan alatu blobrunner. On će **allocate** **shellcode** unutar memorijskog prostora i pokrenuti **eternal loop**. Zatim je potrebno da **attach the debugger** na proces, **play start wait 2-5 secs and press stop** i naći ćete se unutar **eternal loop**. Pređite na sledeću instrukciju eternal loop-a, jer će ona biti poziv shellcode-a, i na kraju ćete se naći u izvršavanju shellcode-a.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it je veoma sličan alatu blobrunner. On će allocate shellcode unutar memorijskog prostora i pokrenuti...](<../../images/image (509).png>)

Kompajliranu verziju alata [jmp2it možete preuzeti na releases stranici](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI alata radare. Pomoću Cutter-a možete emulirati shellcode i dinamički ga analizirati.

Imajte na umu da Cutter omogućava opcije "Open File" i "Open Shellcode". U mom slučaju, kada sam otvorio shellcode kao fajl, decompilovao ga je ispravno, ali kada sam ga otvorio kao shellcode, nije:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Imajte na umu da Cutter omogućava opcije "Open File" i "Open Shellcode". U mom slučaju, kada sam otvorio shellcode kao fajl, ...](<../../images/image (562).png>)

Da biste započeli emulaciju na mestu koje želite, postavite bp tamo i Cutter će, po svemu sudeći, automatski započeti emulaciju od tog mesta:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Da biste započeli emulaciju na mestu koje želite, postavite bp tamo i Cutter će, po svemu sudeći, automatski...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Da biste započeli emulaciju na mestu koje želite, postavite bp tamo i Cutter će, po svemu sudeći, automatski...](<../../images/image (387).png>)

Na primer, stack možete videti unutar hex dump-a:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Na primer, stack možete videti unutar hex dump-a](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Trebalo bi da probate [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Reći će vam stvari poput toga **koje functions** shellcode koristi i da li se shellcode **decoding** u memoriji.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg takođe ima grafički launcher u kojem možete izabrati željene opcije i izvršiti shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

Opcija **Create Dump** će sačuvati finalni shellcode ako je tokom izvršavanja došlo do bilo kakve promene shellcode-a u memoriji (korisno za preuzimanje dekodiranog shellcode-a). Opcija **start offset** može biti korisna za pokretanje shellcode-a od određenog offset-a. Opcija **Debug Shell** korisna je za debugovanje shellcode-a pomoću scDbg terminala (međutim, smatram da je bilo koja od prethodno objašnjenih opcija bolja za ovu svrhu, jer ćete moći da koristite Ida ili x64dbg).

### Disassembling using CyberChef

Otpremite svoj shellcode fajl kao ulaz i koristite sledeći recipe za njegovu dekompilaciju: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation sakriva jednostavne izraze kao što je `x + y` iza formula koje kombinuju aritmetičke (`+`, `-`, `*`) i bitwise operatore (`&`, `|`, `^`, `~`, shifts). Važno je to što su ovi identiteti obično ispravni samo u okviru **fixed-width modular arithmetic**, pa su carry i overflow vrednosti bitni:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Ako ovu vrstu izraza pojednostavite pomoću generičkih algebarskih alata, lako možete dobiti pogrešan rezultat jer je semantika širine bita zanemarena.

### Praktični tok rada

1. **Zadržite originalnu širinu bita** iz podignutog koda/IR-a/dekompajlerskog izlaza (`8/16/32/64` bita).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
- **Linearni**: ponderisane sume bitovskih atoma
- **Semilinearni**: linearni izrazi sa konstantnim maskama kao što je `x & 0xFF`
- **Polinomijalni**: pojavljuju se proizvodi
- **Mešoviti**: proizvodi i bitovska logika su isprepletani, često sa ponovljenim podizrazima
3. **Proverite svaku predloženu transformaciju** nasumičnim testiranjem ili SMT dokazom. Ako ekvivalencija ne može da se dokaže, zadržite originalni izraz umesto da nagađate.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktičan MBA pojednostavljivač za analizu malware-a i reverzno inženjerstvo zaštićenih binarnih fajlova. On klasifikuje izraz i prosleđuje ga specijalizovanim cevovodima, umesto da na sve primenjuje jedan generički prolaz za transformacije.<sup>[[1]](#references)[[2]](#references)</sup>

Brza upotreba:
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

- **Linear MBA**: CoBRA evaluira izraz nad Boolean ulazima, izvodi potpis i paralelno pokreće nekoliko metoda oporavka, kao što su pattern matching, ANF conversion i coefficient interpolation.
- **Semilinear MBA**: atomи maskirani konstantama ponovo se izgrađuju pomoću rekonstrukcije particionisane po bitovima, tako da maskirane oblasti ostanu ispravne.
- **Polynomial/Mixed MBA**: proizvodi se razlažu na jezgra, a ponovljeni podizrazi mogu se izdvojiti u privremene promenljive pre pojednostavljivanja spoljašnje relacije.

Primer mešovitog identiteta koji često vredi pokušati oporaviti:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Ovo se može svesti na:
```c
x * y
```
### Reversing beleške

- Preferirajte pokretanje alata CoBRA nad **lifted IR expressions** ili izlazom dekompajlera nakon što izolujete tačan proračun.
- Eksplicitno koristite `--bitwidth` kada izraz potiče iz maskirane aritmetike ili registara manje širine.
- Ako vam je potreban jači dokazni korak, pogledajte lokalne Z3 beleške ovde:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA se isporučuje i kao **LLVM pass plugin** (`libCobraPass.so`), što je korisno kada želite da normalizujete MBA-heavy LLVM IR pre kasnijih analiza.
- Nepodržane carry-sensitive mixed-domain residuals treba posmatrati kao signal da zadržite originalni izraz i ručno analizirate carry putanju.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuscator **menja sve instrukcije u `mov`** (da, stvarno je kul). Takođe koristi prekide za promenu tokova izvršavanja. Više informacija o tome kako funkcioniše:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Ako budete imali sreće, [demovfuscator](https://github.com/kirschju/demovfuscator) će deofuskirati binarni fajl. Ima nekoliko zavisnosti
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
I [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako igrate **CTF, ovo zaobilaženje za pronalaženje flag-a** može biti veoma korisno: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **ulaznu tačku**, pretražite funkcije po `::main`, kao u primeru:

![Movfuscator - Rust: Da biste pronašli ulaznu tačku, pretražite funkcije po ::main, kao u primeru](<../../images/image (1080).png>)

U ovom slučaju binarni fajl se zvao authenticator, tako da je prilično očigledno da je ovo zanimljiva main funkcija.\
Kada znate **nazive** pozvanih **funkcija**, pretražite ih na **Internetu** da biste saznali više o njihovim **ulazima** i **izlazima**.

### Obnavljanje Rust stringova iz ELF firmware-a

U **Rust ELF** binarnim fajlovima, mnogi statički stringovi nisu referencirani kao C-style pokazivači završeni nulom. Uobičajeni `rustc` raspored je **torka pokazivača/dužine** unutar **`.data.rel.ro`**, koja pokazuje na stvarni blob stringova smešten u **`.rodata`**:<sup>[[3]](#references)</sup>
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
To znači da `strings` ili podrazumevana Ghidra analiza mogu spojiti susedne stringove ili potpuno propustiti cross-reference.

Brzi workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Preuzmite virtuelnu adresu i veličinu sekcije **`.rodata`**.
2. Nabrojte **`.data.rel.ro`** reč po reč.
3. Tretirajte svaku vrednost unutar opsega adresa sekcije `.rodata` kao kandidata za pokazivač na string.
4. Tretirajte sledeću reč kao kandidatsku dužinu.
5. Primijenite sanity filtere (na primer, zadržite dužine između **4** i **100** bajtova).
6. Pročitajte tačno `length` bajtova iz sekcije `.rodata`, umesto skeniranja do `0x00`.

Minimalna logika extractora:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Ovo je posebno korisno pri reverse engineering-u firmware-a, jer pronađeni Rust stringovi često otkrivaju **HTTP rute, RPC nazive, poruke dnevnika, assertions, nazive fajlova, config ključeve, command handlere i logiku povezanu sa autentikacijom**.

Ako Ghidra ne pronađe te stringove, pokrenite prilagođeni script/plugin koji primenjuje istu heuristiku i kreira string podatke na referenciranim `.rodata` offsetima. Objavljeni alati `rust-strings` i `RustStrings.py` kompanije Pen Test Partners predstavljaju dobre reference za prilagođavanje ove ideje drugim **veličinama reči, endianess-u i rasporedima sekcija**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Za Delphi kompajlirane binarne fajlove možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako morate da radite reverse engineering Delphi binarnog fajla, predlažem da koristite IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Samo pritisnite **ATL+f7** (import python plugin-a u IDA-i) i izaberite python plugin.

Ovaj plugin će izvršiti binarni fajl i dinamički razrešiti nazive funkcija na početku debugging-a. Nakon pokretanja debugging-a ponovo pritisnite dugme Start (zeleno dugme ili f9) i breakpoint će se aktivirati na početku pravog koda.

Ovo je takođe veoma zanimljivo jer će se, ako pritisnete dugme u grafičkoj aplikaciji, debugger zaustaviti u funkciji koju to dugme izvršava.

## Golang

Ako morate da radite reverse engineering Golang binarnog fajla, predlažem da koristite IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Samo pritisnite **ATL+f7** (import python plugin-a u IDA-i) i izaberite python plugin.

Ovo će razrešiti nazive funkcija.

## Compiled Python

Na ovoj stranici možete pronaći kako da dobijete python kod iz kompajliranog ELF/EXE python binarnog fajla:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Ako dobijete **binary** GBA igre, možete koristiti različite alate za **emulate** i **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite debug verziju_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

U [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_** ** možete videti kako se pritiskaju **dugmad** Game Boy Advance-a

![konfiguracija kontrola no$gba koja prikazuje mapiranje dugmadi Game Boy Advance-a](<../../images/image (581).png>)

Kada se pritisne, svaki **taster ima vrednost** koja ga identifikuje:
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
Dakle, u ovoj vrsti programa, zanimljiv deo će biti **način na koji program obrađuje korisnički unos**. Na adresi **0x4000130** pronaći ćete često korišćenu funkciju: **KEYINPUT**.

![Ghidra prikaz GBA binarne datoteke koja upućuje na KEYINPUT na adresi 0x4000130](<../../images/image (447).png>)

Na prethodnoj slici možete videti da se funkcija poziva iz **FUN_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekoliko init operacija (bez ikakvog značaja):
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
Poslednji if proverava da li se **`uVar4`** nalazi u poslednjem skupu **Keys** i da nije trenutni taster, što se takođe naziva otpuštanjem dugmeta (trenutni taster se čuva u **`uVar1`**).
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
U prethodnom kodu možete videti da poredimo **uVar1** (mesto gde se nalazi **vrednost pritisnutog dugmeta**) sa nekim vrednostima:

- Najpre se poredi sa **vrednošću 4** (dugme **SELECT**): u izazovu ovo dugme briše ekran
- Zatim se poredi sa **vrednošću 8** (dugme **START**): u izazovu se ovde proverava da li je kod ispravan kako bi se dobio flag.
- U ovom slučaju, var **`DAT_030000d8`** se poredi sa 0xf3 i ako je vrednost ista, izvršava se određeni kod.
- U svim ostalim slučajevima proverava se određeni brojač (**`DAT_030000d4`**). To je brojač zato što se odmah nakon unosa koda uvećava za 1.\
**A**ko je manji od 8, izvršava se nešto što uključuje **sabiranje** vrednosti sa **`DAT_030000d8`** (u osnovi, vrednosti pritisnutih dugmadi se sabiraju u ovu promenljivu sve dok je brojač manji od 8).

Dakle, u ovom izazovu, pošto znate vrednosti dugmadi, trebalo je da **pritisnete kombinaciju kraću od 8 dugmadi čiji zbir iznosi 0xf3.**<sup>[[6]](#references)</sup>

**Referenca za ovaj tutorijal:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursevi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binarna deobfuskacija)

## Reference

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
