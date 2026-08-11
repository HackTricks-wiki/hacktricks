# Alati za reversing i osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## Alati za reversing zasnovani na ImGui

Softver:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) za **dekompajliranje** iz wasm-a (binarni format) u wat (čitljiv tekst)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) za **kompajliranje** iz wat-a u wasm
- Za dekompajliranje možete isprobati i [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Softver:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je decompiler koji **dekompajlira i analizira više formata**, uključujući **biblioteke** (.dll), **Windows metadata datoteke** (.winmd) i **izvršne datoteke** (.exe). Nakon dekompajliranja, assembly se može sačuvati kao Visual Studio projekat (.csproj).

Prednost je u tome što, ako izgubljeni source code treba obnoviti iz legacy assembly-ja, ova radnja može uštedeti vreme. Pored toga, dotPeek omogućava praktičnu navigaciju kroz dekompajlirani code, što ga čini jednim od idealnih alata za **Xamarin analizu algoritama.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Sa sveobuhvatnim add-in modelom i API-jem koji proširuje alat kako bi odgovarao vašim potrebama, .NET reflector štedi vreme i pojednostavljuje development. Pogledajmo mnoštvo reverse engineering funkcionalnosti koje ovaj alat pruža:

- Omogućava uvid u to kako podaci prolaze kroz biblioteku ili komponentu
- Omogućava uvid u implementaciju i upotrebu .NET jezika i framework-a
- Pronalazi nedokumentovanu i neizloženu funkcionalnost kako bi se bolje iskoristili API-ji i korišćene tehnologije.
- Pronalazi dependencies i različite assembly-je
- Pronalazi tačnu lokaciju grešaka u vašem code-u, third-party komponentama i bibliotekama.
- Omogućava debugging izvornog koda svih .NET aplikacija sa kojima radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga direktno instalirati iz VSCode-a, bez potrebe za preuzimanjem git-a. Kliknite na **Extensions** i **pretražite ILSpy**).\
Ako treba da **dekompajlirate**, **izmenite** i ponovo **kompajlirate**, možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Desni klik -> Modify Method** da biste promenili nešto unutar funkcije).

### DNSpy Logging

Da biste omogućili da **DNSpy upisuje određene informacije u fajl**, možete koristiti sledeći snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Da biste debagovali kod koristeći DNSpy, potrebno je da:

Prvo promenite atribute **Assembly** koji se odnose na **debugging**:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

From:
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

Zatim sačuvajte novu datoteku pomoću _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Zatim sačuvajte novu datoteku pomoću File Save module](<../../images/image (602).png>)

Ovo je neophodno zato što će se, ako to ne uradite, tokom **runtime** izvršavanja na kod primeniti različite **optimisations**, pa je moguće da se tokom debugging-a **break-point nikada ne aktivira** ili da neke **varijable ne postoje**.

Zatim, ako se vaša .NET aplikacija **pokreće** preko **IIS-a**, možete je **restartovati** pomoću:
```
iisreset /noforce
```
Zatim, da biste započeli debugging, trebalo bi da zatvorite sve otvorene datoteke i unutar kartice **Debug Tab** izaberete **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste započeli debugging, trebalo bi da zatvorite sve otvorene datoteke i unutar kartice Debug Tab izaberete Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste se povezali sa **IIS serverom** i kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste se povezali sa IIS serverom i kliknite na attach](<../../images/image (113).png>)

Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na _Debug >> Break All_, a zatim kliknite na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim kliknite na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim kliknite na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u odeljku **Modules** i izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u odeljku Modules i izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom miša na bilo koji modul u odeljku **Assembly Explorer** i kliknite na **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom miša na bilo koji modul u odeljku Assembly Explorer i kliknite na Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Učitajte rundll32** (64-bitna verzija se nalazi na C:\Windows\System32\rundll32.exe, a 32-bitna na C:\Windows\SysWOW64\rundll32.exe)
- Izaberite **Windbg** debugger
- Izaberite "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Konfigurišite **parametre** izvršavanja tako što ćete uneti **putanju do DLL-a** i funkciju koju želite da pozovete:

![Debugging DLLs - Using IDA: Konfigurišite parametre izvršavanja tako što ćete uneti putanju do DLL-a i funkciju koju želite da pozovete](<../../images/image (704).png>)

Zatim, kada započnete debugging, **izvršavanje će biti zaustavljeno kada se učita svaki DLL**, pa će, kada rundll32 učita vaš DLL, izvršavanje biti zaustavljeno.

Ovaj metod se zaustavlja pri događajima učitavanja modula, ali je dostizanje entry point-a učitanog DLL-a manje direktno nego u x64dbg workflow-u u nastavku.

### Using x64dbg/x32dbg

- **Učitajte rundll32** (64-bitna verzija se nalazi na C:\Windows\System32\rundll32.exe, a 32-bitna na C:\Windows\SysWOW64\rundll32.exe)
- **Promenite Command Line** ( _File --> Change Command Line_ ) i postavite putanju do dll-a i funkciju koju želite da pozovete, na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Promenite _Options --> Settings_ i izaberite "**DLL Entry**".
- Zatim **započnite izvršavanje**; debugger će se zaustaviti na svakom dll main-u i u jednom trenutku ćete se **zaustaviti na dll Entry vašeg dll-a**. Odatle samo pronađite mesta na koja želite da postavite breakpoint.

Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, možete videti **u kom kodu se nalazite** tako što pogledate **vrh prozora win64dbg-a**:

![Using IDA - Using x64dbg/x32dbg: Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, možete videti u kom kodu se nalazite tako što pogledate vrh prozora win64dbg-a](<../../images/image (842).png>)

Ovaj indikator potvrđuje da je izvršavanje zaustavljeno unutar DLL-a koji želite da debugujete.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje mesta na kojem se važne vrednosti čuvaju u memoriji pokrenute igre i njihovu izmenu. Više informacija nalazi se na:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end/reverse engineering alat za GNU Project Debugger (GDB), usmeren na igre. Međutim, može se koristiti za bilo šta povezano sa reverse engineering-om.

[**Decompiler Explorer**](https://dogbolt.org/) je web front-end za više decompiler-a. Ovaj web servis vam omogućava da uporedite izlaz različitih decompiler-a na malim izvršnim datotekama.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alocira **shellcode**, ispisuje njegovu **memorijsku adresu** i pauzira izvršavanje.\
Povežite debugger kao što su IDA ili x64dbg, postavite breakpoint na ispisanu adresu i nastavite izvršavanje da biste debugovali shellcode.

Github stranica sa releases sadrži zip datoteke sa kompajliranim izdanjima: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blago izmenjenu verziju Blobrunner-a možete pronaći na sledećem linku. Da biste je kompajlirali, samo **kreirajte C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod i build-ujte ga**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je sličan alatu BlobRunner. Alocira shellcode i ulazi u beskonačnu petlju. Povežite debugger, nastavite izvršavanje tokom **2–5 sekundi**, pauzirajte unutar te petlje i izvršavajte korak po korak do sledećeg poziva koji prenosi izvršavanje na alocirani shellcode.

![Debugger paused in jmp2it's infinite loop immediately before the call to the allocated shellcode](<../../images/image (509).png>)

Kompajliranu verziju alata [jmp2it možete preuzeti sa stranice releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI alata radare. Pomoću Cutter-a možete emulirati shellcode i dinamički ga analizirati.

Imajte na umu da Cutter omogućava opcije "Open File" i "Open Shellcode". U mom slučaju, kada sam otvorio shellcode kao datoteku, ispravno ga je dekompajlirao, ali kada sam ga otvorio kao shellcode, nije:

![Cutter showing different analysis results when opening the same bytes as a file or as shellcode](<../../images/image (562).png>)

Da biste emulaciju započeli na mestu koje želite, postavite bp na to mesto; Cutter će, po svemu sudeći, automatski započeti emulaciju odatle:

![Setting a breakpoint at the desired shellcode entry before starting Cutter emulation](<../../images/image (589).png>)

![Cutter emulator paused at the selected shellcode breakpoint](<../../images/image (387).png>)

Na primer, stack možete videti unutar hex dump-a:

![Viewing the emulated shellcode stack in Cutter's hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Trebalo bi da isprobate [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Pokazaće vam stvari kao što su **koje funkcije** shellcode koristi i da li shellcode **dekodira** samog sebe u memoriji.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg takođe ima grafički launcher u kojem možete izabrati željene opcije i izvršiti shellcode

![Grafički launcher scDbg-a za izbor opcija emulacije i tracing-a shellcode-a](<../../images/image (258).png>)

Opcija **Create Dump** će sačuvati završni shellcode ako je shellcode dinamički izmenjen u memoriji (korisno za preuzimanje dekodiranog shellcode-a). Opcija **start offset** može biti korisna za pokretanje shellcode-a na određenom offset-u. Opcija **Debug Shell** korisna je za debugovanje shellcode-a pomoću scDbg terminala (međutim, smatram da je bilo koja od prethodno objašnjenih opcija bolja za ovu svrhu, jer ćete moći da koristite Ida ili x64dbg).

### Disassembling pomoću CyberChef-a

Otpremite svoj shellcode fajl kao ulaz i upotrebite sledeći recept da biste ga dekompilirali: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation skriva jednostavne izraze kao što je `x + y` iza formula koje kombinuju aritmetičke operatore (`+`, `-`, `*`) i bitwise operatore (`&`, `|`, `^`, `~`, shifts). Važno je da su ove identičnosti obično tačne samo u okviru **modularne aritmetike fiksne širine**, tako da su carry i overflow bitni:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Ako ovu vrstu izraza pojednostavite pomoću generičkih algebarskih alata, lako možete dobiti pogrešan rezultat jer je semantika širine bita zanemarena.<sup>[[1]](#references)</sup>

### Praktični tok rada

1. **Zadržite originalnu širinu bita** iz lifted koda/IR/decompiler izlaza (`8/16/32/64` bitova).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
- **Linearni**: ponderisane sume bitwise atoma
- **Semilinearni**: linearni izrazi sa konstantnim maskama kao što je `x & 0xFF`
- **Polinomski**: pojavljuju se proizvodi
- **Mešoviti**: proizvodi i bitwise logika su isprepletani, često sa ponovljenim podizrazima
3. **Proverite svako potencijalno prepisivanje** random testiranjem ili SMT dokazom. Ako ekvivalencija ne može da se dokaže, zadržite originalni izraz umesto da nagađate.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktični MBA pojednostavljivač za analizu malware-a i reversing zaštićenih binarnih fajlova. Klasifikuje izraz i prosleđuje ga kroz specijalizovane pipelines umesto da na sve primenjuje jedan generički rewrite pass.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evaluira izraz na Boolean ulazima, izvodi signature i istovremeno pokreće nekoliko metoda za oporavak, kao što su pattern matching, ANF conversion i coefficient interpolation.
- **Semilinear MBA**: atomi sa constant maskiranjem ponovo se izgrađuju pomoću rekonstrukcije particionisane po bitovima, tako da maskirane oblasti ostanu ispravne.
- **Polynomial/Mixed MBA**: proizvodi se razlažu na jezgra, a ponovljeni podizrazi mogu se izdvojiti u privremene promenljive pre pojednostavljivanja spoljne relacije.

Primer mixed identiteta koji često vredi pokušati oporaviti:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Ovo se može svesti na:
```c
x * y
```
### Beleške o reversing-u

- Prefer running CoBRA on **lifted IR expressions** or decompiler output after you isolated the exact computation.
- Use `--bitwidth` explicitly when the expression came from masked arithmetic or narrow registers.
- If you need a stronger proof step, check the local Z3 notes here:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA takođe dolazi kao **LLVM pass plugin** (`libCobraPass.so`), što je korisno kada želite da normalizujete LLVM IR sa mnogo MBA izraza pre narednih analiza.
- Nepodržane carry-sensitive mixed-domain rezidue treba tretirati kao signal da zadržite originalni izraz i ručno analizirate carry putanju.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuscator zamenjuje operacije programa sekvencama instrukcija zasnovanim na `mov` i koristi signal/exception handling za izmenu toka kontrole. Detalji:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Za podržane binarne fajlove, [demovfuscator](https://github.com/kirschju/demovfuscator) može da deobfuscira rezultat. Ima nekoliko dependencies.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
I [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako radite **CTF, ovo zaobilaženje za pronalaženje flag-a** može biti veoma korisno: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **entry point**, pretražite funkcije pomoću `::main`, kao u primeru:

![Pronalaženje Rust entry point-a u Ghidra-i pretraživanjem naziva funkcija za main sa dvostrukom dvotačkom](<../../images/image (1080).png>)

U ovom slučaju binary se zvao authenticator, tako da je prilično očigledno da je ovo zanimljiva main funkcija.\
Kada znate **nazive** pozvanih **funkcija**, pretražite ih na **Internetu** da biste saznali više o njihovim **ulazima** i **izlazima**.

### Vraćanje Rust stringova iz ELF firmware-a

U **Rust ELF** binary-jima, mnogi statički stringovi nisu referencirani kao C-style pokazivači završeni NUL karakterom. Uobičajeni `rustc` raspored je **tuple pokazivača/dužine** unutar **`.data.rel.ro`**, koji pokazuje na stvarni blob stringa smešten u **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
To znači da `strings` ili podrazumevana Ghidra analiza mogu spojiti susedne stringove ili u potpunosti propustiti cross-reference-ove.<sup>[[3]](#references)</sup>

Brzi tok rada:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Preuzmite virtuelnu adresu i veličinu odeljka **`.rodata`**.
2. Nabrojte odeljak **`.data.rel.ro`** reč po reč.
3. Tretirajte svaku vrednost unutar opsega adresa odeljka `.rodata` kao kandidata za pokazivač na string.
4. Tretirajte sledeću reč kao kandidata za dužinu.
5. Primeni sanity filtere (na primer, zadržite dužine između **4** i **100** bajtova).
6. Pročitajte tačno `length` bajtova iz odeljka `.rodata`, umesto skeniranja do `0x00`.

Minimalna logika ekstraktora:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Ovo je naročito korisno pri reverse engineering-u firmware-a, jer pronađeni Rust strings često otkrivaju **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers i auth-related logic**.

Ako Ghidra ne pronađe te strings, pokrenite custom script/plugin koji primenjuje istu heuristiku i kreira string data na referenciranim `.rodata` offsets. Objavljeni alati `rust-strings` i `RustStrings.py` kompanije Pen Test Partners predstavljaju dobre reference za prilagođavanje ove ideje drugim **word sizes, endianness i section layouts**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Za Delphi kompajlirane binarne fajlove možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako morate da radite reverse engineering Delphi binarnog fajla, predlažem da koristite IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pritisnite **Alt+F7** u IDA-i da učitate Python plugin, a zatim izaberite fajl plugina.

Ovaj plugin će izvršiti binarni fajl i dinamički razrešiti nazive funkcija na početku debugging-a. Nakon pokretanja debugging-a ponovo pritisnite dugme Start (zeleno dugme ili f9) i breakpoint će se aktivirati na početku pravog koda.

Ako pritisnete dugme u grafičkoj aplikaciji, debugger može da se zaustavi u funkciji koju to dugme poziva.

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

Ako dobijete **binary** neke GBA igre, možete koristiti različite alate za **emulate** i **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite debug verziju_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

U programu [**no$gba**](https://problemkaputt.de/gba.htm), u odeljku _**Options --> Emulation Setup --> Controls**_** ** možete videti kako da pritisnete **dugmad** Game Boy Advance konzole

![konfiguracija kontrola u no$gba programu koja prikazuje mapiranje dugmadi Game Boy Advance konzole](<../../images/image (581).png>)

Kada se pritisne, svaki **taster ima vrednost** koja služi za njegovu identifikaciju:
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
Dakle, u ovoj vrsti programa zanimljiv deo biće **kako program obrađuje korisnički unos**. Na adresi **0x4000130** pronaći ćete često korišćenu funkciju: **KEYINPUT**.

![Ghidra prikaz GBA binarne datoteke koja upućuje na KEYINPUT na adresi 0x4000130](<../../images/image (447).png>)

Na prethodnoj slici možete videti da se funkcija poziva iz **FUN_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekoliko operacija inicijalizacije (koje nisu bitne):
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
Poslednji if proverava da li se **`uVar4`** nalazi u poslednjem skupu Keys i da nije trenutni taster, što se takođe naziva otpuštanjem dugmeta (trenutni taster se čuva u **`uVar1`**).
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
U prethodnom kodu možete videti da upoređujemo **uVar1** (mesto na kom se nalazi **vrednost pritisnutog dugmeta**) sa nekim vrednostima:

- Prvo se upoređuje sa **vrednošću 4** (dugme **SELECT**): u ovom izazovu ovo dugme briše ekran
- Zatim se vrednost upoređuje sa **8** (dugme **START**); u ovom izazovu ta grana proverava da li je uneti kod validan.
- U ovom slučaju, varijabla **`DAT_030000d8`** se upoređuje sa 0xf3 i, ako je vrednost ista, izvršava se određeni code.
- U svim ostalim slučajevima proverava se i uvećava brojač (`DAT_030000d4`).\
Dok je brojač manji od 8, vrednosti pritisnutih tastera akumuliraju se u `DAT_030000d8`.

Dakle, u ovom izazovu, pošto znate vrednosti dugmadi, trebalo je da **pritisnete kombinaciju kraću od 8 tastera čiji je zbir 0xf3.**

**Referenca za ovaj tutorijal:** [arhivirani Nostalgia writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursevi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Pojednostavljivanje MBA obfuscation pomoću CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Dekodiranje Rust stringova - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorijal (arhivirano)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
