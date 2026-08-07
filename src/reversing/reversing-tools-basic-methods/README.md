# Alati za Reversing i osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## Alati za Reversing zasnovani na ImGui

Softver:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) za **decompile** iz wasm (binary) u wat (clear text)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) za **compile** iz wat u wasm
- takođe možete pokušati da koristite [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) za decompile

Softver:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je decompiler koji **decompiluje i ispituje više formata**, uključujući **biblioteke** (.dll), **Windows metadata file** (.winmd) i **izvršne fajlove** (.exe). Nakon decompilovanja, assembly se može sačuvati kao Visual Studio projekat (.csproj).

Prednost je u tome što, ako je izgubljeni source code potrebno obnoviti iz legacy assembly-ja, ova radnja može uštedeti vreme. Pored toga, dotPeek pruža praktičnu navigaciju kroz decompilovani code, što ga čini jednim od savršenih alata za **analizu Xamarin algoritama.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Sa sveobuhvatnim add-in modelom i API-jem koji proširuje alat kako bi odgovarao vašim konkretnim potrebama, .NET reflector štedi vreme i pojednostavljuje development. Pogledajmo mnoštvo reverse engineering usluga koje ovaj alat pruža:

- Pruža uvid u to kako podaci prolaze kroz biblioteku ili komponentu
- Pruža uvid u implementaciju i upotrebu .NET jezika i framework-a
- Pronalazi nedokumentovanu i neizloženu funkcionalnost kako bi se izvuklo više iz korišćenih API-ja i tehnologija.
- Pronalazi dependencies i različite assembly-je
- Prati tačnu lokaciju grešaka u vašem code-u, third-party komponentama i bibliotekama.
- Omogućava debugging source-a celokupnog .NET code-a sa kojim radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga direktno instalirati iz VSCode-a, nije potrebno preuzimati git. Kliknite na **Extensions** i **pretražite ILSpy**).\
Ako je potrebno da **decompile**, **modify** i ponovo **recompile** možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegov aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Desni klik -> Modify Method** da biste promenili nešto unutar funkcije).

### DNSpy Logging

Da biste omogućili da **DNSpy loguje neke informacije u fajl**, možete koristiti ovaj snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Da biste otklanjali greške u kodu koristeći DNSpy, potrebno je da:

Prvo promenite **Assembly attributes** povezane sa **debugging**:

![DNSpy Logging - DNSpy Debugging: Prvo promenite Assembly attributes povezane sa debugging](<../../images/image (973).png>)

Iz:
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

![DNSpy Logging - DNSpy Debugging: I kliknite na compile](<../../images/image (314) (1).png>)

Zatim sačuvajte novu datoteku preko _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Zatim sačuvajte novu datoteku preko File Save module](<../../images/image (602).png>)

Ovo je neophodno zato što će, ako to ne uradite, tokom **runtime** biti primenjene određene **optimizacije** na kod i moguće je da tokom debugging-a **break-point nikada neće biti dostignut** ili da neke **promenljive ne postoje**.

Zatim, ako se vaša .NET aplikacija **pokreće** preko **IIS-a**, možete je **restartovati** pomoću:
```
iisreset /noforce
```
Zatim, da biste započeli debugging, zatvorite sve otvorene fajlove i unutar **Debug Tab** izaberite **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste započeli debugging, zatvorite sve otvorene fajlove i unutar Debug Tab izaberite Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste ga povezali sa **IIS serverom** i kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste ga povezali sa IIS serverom i kliknite na attach](<../../images/image (113).png>)

Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na _Debug >> Break All_, a zatim kliknite na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim kliknite na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim kliknite na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u odeljku **Modules** i izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u odeljku Modules i izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom miša na bilo koji modul u **Assembly Explorer** i kliknite na **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom miša na bilo koji modul u Assembly Explorer i kliknite na Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64-bitni se nalazi u C:\Windows\System32\rundll32.exe, a 32-bitni u C:\Windows\SysWOW64\rundll32.exe)
- Izaberite **Windbg** debugger
- Izaberite "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Konfigurišite **parameters** izvršavanja tako što ćete uneti **path do DLL-a** i funkciju koju želite da pozovete:

![Debugging DLLs - Using IDA: Konfigurišite parameters izvršavanja tako što ćete uneti path do DLL-a i funkciju koju želite da pozovete](<../../images/image (704).png>)

Zatim, kada započnete debugging, **izvršavanje će biti zaustavljeno svaki put kada se učita DLL**, pa će, kada rundll32 učita vaš DLL, izvršavanje biti zaustavljeno.

Ali kako možete doći do koda učitanog DLL-a? Koristeći ovaj metod, ne znam kako.

### Using x64dbg/x32dbg

- **Load rundll32** (64-bitni se nalazi u C:\Windows\System32\rundll32.exe, a 32-bitni u C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) i postavite putanju do DLL-a i funkciju koju želite da pozovete, na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Promenite _Options --> Settings_ i izaberite "**DLL Entry**".
- Zatim **pokrenite izvršavanje**; debugger će se zaustaviti na svakom dll main-u i u jednom trenutku ćete se **zaustaviti na dll Entry vašeg DLL-a**. Odatle samo pronađite tačke na koje želite da postavite breakpoint.

Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, možete videti **u kom kodu se nalazite** gledajući **vrh prozora win64dbg-a**:

![Using IDA - Using x64dbg/x32dbg: Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, možete videti u kom kodu se nalazite gledajući vrh prozora win64dbg-a](<../../images/image (842).png>)

Na taj način možete videti kada je izvršavanje zaustavljeno u DLL-u koji želite da debugujete.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje mesta na kojima se važne vrednosti čuvaju unutar memorije pokrenute igre i njihovu izmenu. Više informacija u:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end/reverse engineering alat za GNU Project Debugger (GDB), fokusiran na igre. Međutim, može se koristiti za sve što je povezano sa reverse engineeringom.

[**Decompiler Explorer**](https://dogbolt.org/) je web front-end za više decompiler-a. Ovaj web servis vam omogućava da uporedite izlaz različitih decompiler-a na malim executable fajlovima.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) će **alokirati** **shellcode** unutar memorijskog prostora, **prikazati** vam **memorijsku adresu** na kojoj je shellcode alociran i **zaustaviti** izvršavanje.\
Zatim treba da se **povežete debuggerom** (Ida ili x64dbg) sa procesom, postavite **breakpoint na navedenu memorijsku adresu** i **nastavite** izvršavanje. Na ovaj način ćete debugovati shellcode.

GitHub releases stranica sadrži zip fajlove sa kompajliranim izdanjima: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Nešto izmenjenu verziju Blobrunner-a možete pronaći na sledećem linku. Da biste je kompajlirali, samo **kreirajte C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod i build-ujte ga**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je veoma sličan blobrunner-u. On će **alokirati** **shellcode** unutar memorijskog prostora i pokrenuti **beskonačnu petlju**. Zatim treba da se **povežete debuggerom** sa procesom, **kliknete na start, sačekate 2-5 sekundi i pritisnete stop**, nakon čega ćete se naći unutar **beskonačne petlje**. Pređite na sledeću instrukciju beskonačne petlje, jer će ona biti poziv shellcode-a, i na kraju ćete se naći u procesu izvršavanja shellcode-a.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it je veoma sličan blobrunner-u. On će alocirati shellcode unutar memorijskog prostora i pokrenuti...](<../../images/image (509).png>)

Kompajliranu verziju alata [jmp2it možete preuzeti na releases stranici](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI za radare. Koristeći Cutter možete emulirati shellcode i dinamički ga analizirati.

Imajte na umu da Cutter omogućava opcije "Open File" i "Open Shellcode". U mom slučaju, kada sam otvorio shellcode kao fajl, pravilno ga je dekompajlirao, ali kada sam ga otvorio kao shellcode, nije:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Imajte na umu da Cutter omogućava opcije "Open File" i "Open Shellcode". U mom slučaju, kada sam otvorio shellcode kao fajl...](<../../images/image (562).png>)

Da biste pokrenuli emulaciju na mestu koje želite, postavite bp na to mesto i Cutter će, po svemu sudeći, automatski pokrenuti emulaciju odatle:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Da biste pokrenuli emulaciju na mestu koje želite, postavite bp na to mesto i Cutter će, po svemu sudeći, automatski...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Da biste pokrenuli emulaciju na mestu koje želite, postavite bp na to mesto i Cutter će, po svemu sudeći, automatski...](<../../images/image (387).png>)

Na primer, stack možete videti unutar hex dump-a:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Na primer, stack možete videti unutar hex dump-a](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Trebalo bi da isprobate [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Pokazaće vam stvari kao što su **koje funkcije** shellcode koristi i da li se shellcode **dekodira** u memoriji.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg takođe dolazi sa grafičkim launcherom u kojem možete izabrati željene opcije i izvršiti shellcode

![Debugovanje shellcode-a pomoću Cutter-a - Deobfuskacija shellcode-a i pronalaženje izvršenih funkcija: scDbg takođe dolazi sa grafičkim launcherom u kojem možete izabrati željene opcije i...](<../../images/image (258).png>)

Opcija **Create Dump** sačuvaće konačni shellcode ako se tokom izvršavanja dinamički izvrši bilo kakva izmena shellcode-a u memoriji (korisno za preuzimanje dekodiranog shellcode-a). Opcija **start offset** može biti korisna za pokretanje shellcode-a od određenog offseta. Opcija **Debug Shell** korisna je za debugovanje shellcode-a pomoću scDbg terminala (međutim, smatram da su bilo koje od prethodno objašnjenih opcija bolje za ovu svrhu, jer ćete moći da koristite Idu ili x64dbg).

### Disasembliranje pomoću CyberChef-a

Otpremite datoteku sa shellcode-om kao ulaz i upotrebite sledeći recept da biste je disasemblirali: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuskacija skriva jednostavne izraze kao što je `x + y` iza formula koje kombinuju aritmetičke operatore (`+`, `-`, `*`) i bitovske operatore (`&`, `|`, `^`, `~`, pomeranja). Važno je da su ovi identiteti obično tačni samo u uslovima **modularne aritmetike fiksne širine**, tako da su prenosni bitovi i prekoračenja važni:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Ako pojednostavite ovu vrstu izraza pomoću generičkih alata za algebru, lako možete dobiti pogrešan rezultat jer je semantika širine bita zanemarena.<sup>[[1]](#references)</sup>

### Praktičan tok rada

1. **Zadržite originalnu širinu bita** iz izlaza lifted koda/IR-a/dekompilatora (`8/16/32/64` bitova).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
- **Linearni**: ponderisane sume bitwise atoma
- **Semilinearni**: linearni izrazi plus konstantne maske kao što je `x & 0xFF`
- **Polinomski**: pojavljuju se proizvodi
- **Mešoviti**: proizvodi i bitwise logika su isprepletani, često sa ponovljenim podizrazima
3. **Proverite svaku predloženu transformaciju** nasumičnim testiranjem ili SMT dokazom. Ako se ekvivalencija ne može dokazati, zadržite originalni izraz umesto da nagađate.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktičan MBA simplifikator za analizu malvera i reverse engineering zaštićenih binarnih fajlova. Klasifikuje izraz i prosleđuje ga kroz specijalizovane pipeline-ove, umesto da na sve primenjuje jedan generički prolaz za transformaciju.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evaluira izraz na Boolean ulazima, izvodi signature i pokreće nekoliko metoda za oporavak, kao što su pattern matching, ANF conversion i coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms se ponovo izgrađuju pomoću bit-partitioned reconstruction, tako da maskirane oblasti ostanu ispravne.
- **Polynomial/Mixed MBA**: proizvodi se rastavljaju na core komponente, a ponovljeni podizrazi mogu se izdvojiti u privremene promenljive pre pojednostavljivanja spoljne relacije.

Primer mixed identiteta koji obično vredi pokušati oporaviti:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Ovo se može svesti na:
```c
x * y
```
### Napomene o reversing-u

- Prednost dajte pokretanju alata CoBRA nad **lifted IR izrazima** ili izlazom decompiler-a nakon što izolujete tačan proračun.
- Eksplicitno koristite `--bitwidth` kada je izraz nastao iz maskirane aritmetike ili registara manje širine.
- Ako vam je potreban jači dokazni korak, pogledajte lokalne Z3 napomene ovde:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA se takođe isporučuje kao **LLVM pass plugin** (`libCobraPass.so`), što je korisno kada želite da normalizujete LLVM IR sa mnogo MBA konstrukcija pre kasnijih analysis pass-ova.
- Nepodržane mixed-domain rezidue osetljive na carry treba posmatrati kao signal da zadržite originalni izraz i ručno analizirate carry putanju.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuscator **menja sve instrukcije u `mov`** (da, zaista je kul). Takođe koristi prekide za promenu tokova izvršavanja. Više informacija o tome kako funkcioniše:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Ako imate sreće, [demovfuscator](https://github.com/kirschju/demovfuscator) će deofuskovati binary. Ima nekoliko dependencies.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
I [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako radite **CTF, ovaj workaround za pronalaženje flag-a** može biti veoma koristan: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **entry point**, pretražite funkcije po `::main`, kao u:

![Movfuscator - Rust: Da biste pronašli entry point, pretražite funkcije po ::main, kao u](<../../images/image (1080).png>)

U ovom slučaju binary se zvao authenticator, pa je prilično očigledno da je ovo zanimljiva main funkcija.\
Na **Internetu** pretražite **name** pozvanih **functions** da biste saznali više o njihovim **inputs** i **outputs**.

### Ponovno dobijanje Rust stringova iz ELF firmware-a

U **Rust ELF** binary-jima, mnogi static stringovi nisu referencirani kao C-style NUL-terminated pointers. Uobičajeni `rustc` layout je **pointer/length tuple** unutar **`.data.rel.ro`**, koji pokazuje na stvarni string blob smešten u **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
To znači da `strings` ili podrazumevana Ghidra analiza mogu spojiti susedne stringove ili u potpunosti propustiti cross-reference-ove.<sup>[[3]](#references)</sup>

Brzi tok rada:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Preuzmite virtuelnu adresu i veličinu sekcije **`.rodata`**.
2. Nabrajajte **`.data.rel.ro`** reč po reč.
3. Tretirajte svaku vrednost unutar opsega adresa sekcije `.rodata` kao potencijalni pokazivač na string.
4. Tretirajte sledeću reč kao potencijalnu dužinu.
5. Primenite sanity filtere (na primer, zadržite dužine između **4** i **100** bajtova).
6. Pročitajte tačno `length` bajtova iz `.rodata` umesto skeniranja do `0x00`.

Minimalna logika extractora:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Ovo je posebno korisno pri reverse engineeringu firmware-a, jer pronađeni Rust stringovi često otkrivaju **HTTP rute, RPC nazive, poruke logova, assertions, imena fajlova, config ključeve, command handlere i logiku povezanu sa autentifikacijom**.

Ako Ghidra ne pronađe te stringove, pokrenite prilagođeni script/plugin koji primenjuje istu heuristiku i kreira string podatke na referenciranim `.rodata` offsetima. Objavljeni alati `rust-strings` i `RustStrings.py` kompanije Pen Test Partners predstavljaju dobre reference za prilagođavanje ove ideje drugim **veličinama reči, endianness-ima i rasporedima sekcija**.<sup>[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Za Delphi kompajlovane binarne fajlove možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako morate da radite reverse engineering Delphi binarnog fajla, preporučujem da koristite IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Samo pritisnite **ATL+f7** (import python plugina u IDA-i) i izaberite python plugin.

Ovaj plugin će izvršiti binarni fajl i dinamički razrešiti nazive funkcija na početku debugginga. Nakon pokretanja debugginga ponovo pritisnite dugme Start (zeleno dugme ili f9) i breakpoint će se aktivirati na početku stvarnog koda.

Ovo je takođe veoma zanimljivo zato što će se, ako pritisnete dugme u grafičkoj aplikaciji, debugger zaustaviti u funkciji koju je to dugme izvršilo.

## Golang

Ako morate da radite reverse engineering Golang binarnog fajla, preporučujem da koristite IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Samo pritisnite **ATL+f7** (import python plugina u IDA-i) i izaberite python plugin.

Ovo će razrešiti nazive funkcija.

## Kompajlovani Python

Na ovoj stranici možete pronaći kako da dobijete python kod iz ELF/EXE python kompajlovanog binarnog fajla:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Ako nabavite **binary** GBA igre, možete koristiti različite alate za njenu **emulaciju** i **debugging**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite debug verziju_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

U programu [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_** ** možete videti kako da pritisnete Game Boy Advance **dugmad**

![no$gba konfiguracija kontrola koja prikazuje mapiranje dugmadi Game Boy Advance uređaja](<../../images/image (581).png>)

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
Dakle, u ovoj vrsti programa zanimljiv deo biće **način na koji program obrađuje korisnički unos**. Na adresi **0x4000130** pronaći ćete često korišćenu funkciju: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

Na prethodnoj slici možete videti da se funkcija poziva iz funkcije **FUN_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekoliko inicijalizacionih operacija (koje nisu važne):
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
Poslednji **`if`** proverava da li se **`uVar4`** nalazi u poslednjem nizu **Keys** i da nije trenutni taster, što se takođe naziva otpuštanjem dugmeta (trenutni taster se čuva u **`uVar1`**).
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

- Prvo se poredi sa **vrednošću 4** (dugme **SELECT**): u challenge-u ovo dugme briše ekran
- Zatim se poredi sa **vrednošću 8** (dugme **START**): u challenge-u se ovde proverava da li je code validan da bi se dobio flag.
- U ovom slučaju, var **`DAT_030000d8`** se poredi sa 0xf3 i ako je vrednost ista, izvršava se određeni code.
- U svim ostalim slučajevima proverava se neki cont (**`DAT_030000d4`**). To je cont zato što se odmah nakon unošenja code-a povećava za 1.\
**A**ko je manji od 8, izvršava se nešto što uključuje **sabiranje** vrednosti sa **`DAT_030000d8`** (u osnovi se vrednosti pritisnutih dugmadi sabiraju u ovoj promenljivoj sve dok je cont manji od 8).

Dakle, u ovom challenge-u, znajući vrednosti dugmadi, trebalo je da **pritisnete kombinaciju kraću od 8 dugmadi čiji je zbir 0xf3.**

**Referenca za ovaj tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursevi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## Reference

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
