# Alati za Reverse Engineering i osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## Alati za Reverse Engineering zasnovani na ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) za **dekompajliranje** iz wasm-a (binary) u wat (clear text)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) za **kompajliranje** iz wat-a u wasm
- Za dekompajliranje možete isprobati i [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je decompiler koji **dekompajlira i ispituje više formata**, uključujući **libraries** (.dll), **Windows metadata files** (.winmd) i **executables** (.exe). Nakon dekompajliranja, assembly se može sačuvati kao Visual Studio projekat (.csproj).

Prednost je u tome što, ako izgubljeni source code zahteva restauraciju iz legacy assembly-ja, ova radnja može uštedeti vreme. Pored toga, dotPeek pruža praktičnu navigaciju kroz dekompajlirani code, što ga čini jednim od savršenih alata za **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Sa sveobuhvatnim add-in modelom i API-jem koji proširuje alat kako bi odgovarao vašim tačnim potrebama, .NET reflector štedi vreme i pojednostavljuje development. Pogledajmo mnoštvo reverse engineering usluga koje ovaj alat pruža:

- Pruža uvid u to kako podaci prolaze kroz library ili component
- Pruža uvid u implementaciju i upotrebu .NET jezika i framework-a
- Pronalazi nedokumentovanu i neizloženu funkcionalnost kako bi se izvuklo više iz korišćenih API-ja i tehnologija.
- Pronalazi dependencies i različite assemblies
- Prati tačnu lokaciju grešaka u vašem code-u, third-party components i libraries.
- Omogućava debugging u source-u celokupnog .NET code-a sa kojim radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga direktno instalirati iz VSCode-a, nema potrebe da preuzimate git. Kliknite na **Extensions** i **search ILSpy**).\
Ako treba da **decompile**, **modify** i ponovo **recompile**, možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** da biste promenili nešto unutar funkcije).

### DNSpy Logging

Da bi **DNSpy logovao određene informacije u fajl**, možete koristiti sledeći snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Da biste otklanjali greške u kodu koristeći DNSpy, potrebno je da:

Najpre promenite **Assembly attributes** povezane sa **debugging**:

![DNSpy Logging - DNSpy Debugging: Najpre promenite Assembly attributes povezane sa debugging](<../../images/image (973).png>)

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

Zatim sačuvajte novu datoteku putem _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Zatim sačuvajte novu datoteku putem File Save module](<../../images/image (602).png>)

Ovo je neophodno zato što će se, ako to ne uradite, tokom **runtime**-a na kod primeniti nekoliko **optimisations**, pa je moguće da se tokom debugging-a **break-point nikada ne aktivira** ili da neke **variables ne postoje**.

Zatim, ako se vaša .NET aplikacija **pokreće** preko **IIS**-a, možete je **restartovati** pomoću:
```
iisreset /noforce
```
Zatim, da biste započeli debugging, trebalo bi da zatvorite sve otvorene fajlove i u **Debug Tab** izaberete **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste započeli debugging, trebalo bi da zatvorite sve otvorene fajlove i u Debug Tab izaberete Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste ga povezali sa **IIS serverom** i kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste ga povezali sa IIS serverom i kliknite na attach](<../../images/image (113).png>)

Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na _Debug >> Break All_, a zatim na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u prozoru **Modules** i izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u prozoru Modules i izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom miša na bilo koji modul u **Assembly Explorer** i kliknite na **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom miša na bilo koji modul u Assembly Explorer i kliknite na Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLL-ova

### Korišćenje IDA-e

- **Učitajte rundll32** (64-bitni se nalazi u C:\Windows\System32\rundll32.exe, a 32-bitni u C:\Windows\SysWOW64\rundll32.exe)
- Izaberite **Windbg** debugger
- Izaberite "**Suspend on library load/unload**"

![Debugging DLL-ova - Korišćenje IDA-e: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Konfigurišite **parameters** izvršavanja tako što ćete uneti **path do DLL-a** i funkciju koju želite da pozovete:

![Debugging DLL-ova - Korišćenje IDA-e: Konfigurišite parameters izvršavanja tako što ćete uneti path do DLL-a i funkciju koju želite da pozovete](<../../images/image (704).png>)

Zatim, kada započnete debugging, **izvršavanje će biti zaustavljeno kada se učita svaki DLL**, pa će, kada rundll32 učita vaš DLL, izvršavanje biti zaustavljeno.

Ovaj metod se zaustavlja pri događajima učitavanja modula, ali je dostizanje entry point-a učitanog DLL-a manje direktno nego kod x64dbg workflow-a u nastavku.

### Korišćenje x64dbg/x32dbg

- **Učitajte rundll32** (64-bitni se nalazi u C:\Windows\System32\rundll32.exe, a 32-bitni u C:\Windows\SysWOW64\rundll32.exe)
- **Promenite Command Line** ( _File --> Change Command Line_ ) i postavite path do dll-a i funkciju koju želite da pozovete, na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Promenite _Options --> Settings_ i izaberite "**DLL Entry**".
- Zatim **započnite izvršavanje**; debugger će se zaustaviti na svakom dll main-u i u jednom trenutku ćete se **zaustaviti u dll Entry vašeg dll-a**. Odatle samo pronađite mesta na koja želite da postavite breakpoint.

Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, možete videti **u kom kodu se nalazite** tako što ćete pogledati **vrh prozora win64dbg-a**:

![Korišćenje IDA-e - Korišćenje x64dbg/x32dbg: Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, možete videti u kom kodu se nalazite na vrhu prozora win64dbg-a](<../../images/image (842).png>)

Ovaj indikator potvrđuje kada je izvršavanje zaustavljeno unutar DLL-a koji želite da debugujete.

## GUI aplikacije / videoigre

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje mesta na kojima se važne vrednosti čuvaju unutar memorije pokrenute igre i njihovu izmenu. Više informacija:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end/reverse engineering alat za GNU Project Debugger (GDB), usmeren na igre. Međutim, može se koristiti za bilo šta povezano sa reverse engineering-om.

[**Decompiler Explorer**](https://dogbolt.org/) je web front-end za veliki broj decompilera. Ovaj web servis vam omogućava da uporedite izlaz različitih decompilera na malim izvršnim fajlovima.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging shellcode-a pomoću blobrunner-a

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alocira **shellcode**, ispisuje njegovu **memory address** i pauzira izvršavanje.\
Povežite debugger, kao što su IDA ili x64dbg, postavite breakpoint na ispisanu adresu i nastavite izvršavanje da biste debugovali shellcode.

Github stranica sa releases sadrži zip fajlove sa kompajliranim izdanjima: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blago izmenjenu verziju Blobrunner-a možete pronaći na sledećem linku. Da biste je kompajlirali, samo **kreirajte C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod i build-ujte ga**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging shellcode-a pomoću jmp2it-a

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je sličan alatu BlobRunner. Alocira shellcode i ulazi u beskonačnu petlju. Povežite debugger, nastavite izvršavanje **2–5 sekundi**, pauzirajte unutar te petlje i izvršite step do sledećeg poziva koji prenosi izvršavanje na alocirani shellcode.

![Debugger pauziran u beskonačnoj petlji jmp2it-a neposredno pre poziva alociranog shellcode-a](<../../images/image (509).png>)

Kompajliranu verziju alata [jmp2it možete preuzeti na releases stranici](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode-a pomoću Cutter-a

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI alata radare. Pomoću Cutter-a možete emulirati shellcode i dinamički ga analizirati.

Imajte na umu da Cutter omogućava opcije "Open File" i "Open Shellcode". U mom slučaju, kada sam otvorio shellcode kao fajl, ispravno ga je dekompajlirao, ali kada sam ga otvorio kao shellcode, nije:

![Cutter prikazuje različite rezultate analize pri otvaranju istih bajtova kao fajla ili kao shellcode-a](<../../images/image (562).png>)

Da biste započeli emulaciju na mestu koje želite, tamo postavite bp i Cutter će, po svemu sudeći, automatski započeti emulaciju od tog mesta:

![Postavljanje breakpoint-a na željeni entry shellcode-a pre pokretanja Cutter emulacije](<../../images/image (589).png>)

![Cutter emulator pauziran na izabranom breakpoint-u shellcode-a](<../../images/image (387).png>)

Na primer, stack možete videti unutar hex dump-a:

![Prikaz emuliranog stack-a shellcode-a u Cutter-ovom hex dump-u](<../../images/image (186).png>)

### Deobfuscating shellcode-a i pronalaženje izvršenih funkcija

Trebalo bi da isprobate [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Reći će vam stvari poput toga **koje funkcije** shellcode koristi i da li se shellcode **decoding-uje** u memoriji.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg takođe poseduje grafički pokretač u kojem možete izabrati željene opcije i izvršiti shellcode

![Grafički pokretač scDbg-a za izbor opcija emulacije i praćenja shellcode-a](<../../images/image (258).png>)

Opcija **Create Dump** izbacuje konačni shellcode ako je shellcode dinamički izmenjen u memoriji (korisno za preuzimanje dekodiranog shellcode-a). Opcija **start offset** može biti korisna za pokretanje shellcode-a na određenom offsetu. Opcija **Debug Shell** korisna je za otklanjanje grešaka u shellcode-u pomoću scDbg terminala (međutim, smatram da su bilo koje od prethodno objašnjenih opcija bolje za ovu namenu, jer ćete moći da koristite Ida ili x64dbg).

### Disasembliranje pomoću CyberChef-a

Otpremite svoj shellcode fajl kao ulaz i upotrebite sledeći recept da biste ga disasemblirali: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Dekodiranje MBA obfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation skriva jednostavne izraze kao što je `x + y` iza formula koje kombinuju aritmetičke (`+`, `-`, `*`) i bitovske operatore (`&`, `|`, `^`, `~`, pomeranja). Važno je da su ovi identiteti obično ispravni samo u okviru **modularne aritmetike fiksne širine**, zbog čega su prenosi i prekoračenja bitni:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Ako ovu vrstu izraza pojednostavite pomoću generičkih alata za algebru, lako možete dobiti pogrešan rezultat jer je semantika širine bitova zanemarena.<sup>[[1]](#references)</sup>

### Praktični tok rada

1. **Zadržite originalnu širinu bitova** iz lifted koda/IR/decompiler izlaza (`8/16/32/64` bita).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
- **Linearni**: ponderisani zbirovi bitwise atoma
- **Semilinearni**: linearni izrazi uvećani za konstantne maske kao što je `x & 0xFF`
- **Polinomski**: pojavljuju se proizvodi
- **Mešoviti**: proizvodi i bitwise logika su isprepletani, često sa ponovljenim podizrazima
3. **Proverite svaku potencijalnu transformaciju** pomoću nasumičnog testiranja ili SMT dokaza. Ako se ekvivalencija ne može dokazati, zadržite originalni izraz umesto da nagađate.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktični MBA simplifier za analizu malware-a i reversing zaštićenih binarnih fajlova. On klasifikuje izraz i usmerava ga kroz specijalizovane pipeline-ove umesto da na sve primenjuje jedan generički rewrite pass.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evaluira izraz nad Boolean ulazima, izvodi potpis i paralelno pokreće nekoliko metoda za oporavak, kao što su uparivanje obrazaca, ANF konverzija i interpolacija koeficijenata.
- **Semilinear MBA**: atomi sa konstantnom maskom ponovo se izgrađuju rekonstrukcijom particionisanom po bitovima, tako da maskirani regioni ostanu ispravni.
- **Polynomial/Mixed MBA**: proizvodi se razlažu na jezgra, a ponovljeni podizrazi mogu se izdvojiti u privremene promenljive pre pojednostavljivanja spoljne relacije.

Primer mešovitog identiteta koji često vredi pokušati oporaviti:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Ovo se može svesti na:
```c
x * y
```
### Beleške o Reversing-u

- Prednost dajte pokretanju CoBRA nad **lifted IR expressions** ili izlazom decompiler-a nakon što izolujete tačno izračunavanje.
- Koristite `--bitwidth` eksplicitno kada je izraz potekao iz maskirane aritmetike ili registara male širine.
- Ako vam je potreban jači proof korak, proverite lokalne Z3 beleške ovde:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA se takođe isporučuje kao **LLVM pass plugin** (`libCobraPass.so`), što je korisno kada želite da normalizujete MBA-heavy LLVM IR pre kasnijih analysis pass-ova.
- Nepodržane carry-sensitive mixed-domain rezidue treba tretirati kao signal da zadržite originalni izraz i ručno analizirate carry path.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuscator zamenjuje programske operacije sekvencama instrukcija zasnovanim na `mov` i koristi signal/exception handling za izmenu control flow-a. Detalji:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Za podržane binarne fajlove, [demovfuscator](https://github.com/kirschju/demovfuscator) može da deobfuscate-uje rezultat. Ima nekoliko dependencies.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
I [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako radite **CTF, ovaj workaround za pronalaženje flag-a** može biti veoma koristan: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **entry point**, pretražite funkcije pomoću `::main`, kao u primeru:

![Pronalaženje Rust entry point-a u Ghidri pretraživanjem naziva funkcija za main sa dvostrukom dvotačkom](<../../images/image (1080).png>)

U ovom slučaju binary se zvao authenticator, pa je prilično očigledno da je to zanimljiva main funkcija.\
Kada znate **nazive** pozvanih **funkcija**, pretražite ih na **Internetu** da biste saznali više o njihovim **ulazima** i **izlazima**.

### Rekonstrukcija Rust stringova iz ELF firmware-a

U **Rust ELF** binary-jima, mnogi statički stringovi nisu referencirani kao C-style pokazivači završeni sa NUL znakom. Uobičajeni `rustc` raspored je **tuple pokazivača/dužine** unutar **`.data.rel.ro`**, koji pokazuje na stvarni blob stringa smešten u **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
To znači da `strings` ili podrazumevana Ghidra analiza mogu spojiti susedne stringove ili u potpunosti propustiti unakrsne reference.<sup>[[3]](#references)</sup>

Brzi tok rada:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Dobijte virtuelnu adresu i veličinu **`.rodata`**.
2. Nabrojte **`.data.rel.ro`** jednu reč po jednu.
3. Tretirajte svaku vrednost unutar opsega adresa **`.rodata`** kao kandidata za pokazivač na string.
4. Tretirajte sledeću reč kao kandidatsku dužinu.
5. Primenite sanity filtere (na primer, zadržite dužine između **4** i **100** bajtova).
6. Pročitajte tačno `length` bajtova iz **`.rodata`** umesto skeniranja do `0x00`.

Minimalna logika ekstraktora:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Ovo je posebno korisno pri reverse engineeringu firmware-a, jer pronađeni Rust stringovi često otkrivaju **HTTP rute, RPC nazive, log poruke, assertions, nazive fajlova, config ključeve, command handlers i logiku povezanu sa autentikacijom**.

Ako Ghidra ne pronađe te stringove, pokrenite custom script/plugin koji primenjuje istu heuristiku i kreira string podatke na referenciranim `.rodata` offsetima. Objavljeni alati `rust-strings` i `RustStrings.py` kompanije Pen Test Partners predstavljaju dobre reference za prilagođavanje ove ideje drugim **veličinama reči, endianness-u i rasporedima sekcija**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Za Delphi kompajlirane binarne fajlove možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako morate da radite reverse engineering Delphi binarnog fajla, predlažem da koristite IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pritisnite **Alt+F7** u IDA-i da učitate Python plugin, a zatim izaberite fajl plugina.

Ovaj plugin će izvršiti binarni fajl i dinamički razrešiti nazive funkcija na početku debugging-a. Nakon pokretanja debugging-a ponovo pritisnite dugme Start (zeleno dugme ili f9) i breakpoint će se aktivirati na početku pravog koda.

Ako pritisnete dugme u grafičkoj aplikaciji, debugger može da se zaustavi u funkciji koju je to dugme pozvalo.

## Golang

Ako morate da radite reverse engineering Golang binarnog fajla, predlažem da koristite IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pritisnite **Alt+F7** u IDA-i da učitate Python plugin, a zatim izaberite fajl plugina.

Ovo će razrešiti nazive funkcija.

## Kompajlirani Python

Na ovoj stranici možete pronaći kako da dobijete Python kod iz ELF/EXE Python kompajliranog binarnog fajla:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ako dobijete **binary** GBA igre, možete koristiti različite alate za njenu **emulaciju** i **debugging**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite debug verziju_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

U [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_** ** možete videti kako se pritiskaju **dugmad** na Game Boy Advance-u

![konfiguracija no$gba kontrola koja prikazuje mapiranja dugmadi na Game Boy Advance-u](<../../images/image (581).png>)

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
Dakle, kod ove vrste programa, zanimljiv deo će biti **kako program obrađuje korisnički unos**. Na adresi **0x4000130** pronaći ćete često korišćenu funkciju: **KEYINPUT**.

![Ghidra prikaz GBA binarne datoteke koja referencira KEYINPUT na adresi 0x4000130](<../../images/image (447).png>)

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
Poslednji `if` proverava da li se **`uVar4`** nalazi u **poslednjem Keys** i da nije trenutni taster; to se takođe naziva otpuštanjem dugmeta (trenutni taster se čuva u **`uVar1`**).
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
U prethodnom kodu možete videti da poredimo **uVar1** (mesto gde se nalazi **vrednost pritisnutog dugmeta**) sa određenim vrednostima:

- Prvo se poredi sa **vrednošću 4** (dugme **SELECT**): u challenge-u ovo dugme briše ekran
- Zatim se vrednost poredi sa **8** (dugme **START**); u ovom challenge-u ta putanja proverava da li je uneti kod validan.
- U ovom slučaju, var **`DAT_030000d8`** se poredi sa 0xf3 i ako je vrednost ista, izvršava se određeni kod.
- U svim ostalim slučajevima proverava se i uvećava brojač (`DAT_030000d4`).\
Dok je brojač manji od 8, vrednosti pritisnutih tastera se akumuliraju u `DAT_030000d8`.

Dakle, u ovom challenge-u, znajući vrednosti dugmadi, trebalo je da **pritisnete kombinaciju dužine manje od 8 čiji je zbir 0xf3.**

**Referenca za ovaj tutorijal:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursevi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Pojednostavljivanje MBA obfuscation-a pomoću CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [CoBRA repository kompanije Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Dekodiranje Rust stringova - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorijal (arhivirano)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
