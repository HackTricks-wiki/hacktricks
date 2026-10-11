# Alati za reverzno inženjerstvo i osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## Alati za reverzno inženjerstvo zasnovani na ImGui

Softver:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Debugovanje Windows kernela

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Na mreži:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) za **dekompilaciju** iz wasm (binarnog formata) u wat (čitljiv tekst)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) za **kompilaciju** iz wat u wasm
- Za dekompilaciju možete probati i [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Softver:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 keširani bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je decompiler koji **dekompajlira i analizira više formata**, uključujući **biblioteke** (.dll), **datoteke Windows metapodataka** (.winmd) i **izvršne datoteke** (.exe). Nakon dekompilacije, assembly se može sačuvati kao Visual Studio projekat (.csproj).

Prednost je u tome što ovaj postupak može da uštedi vreme kada je potrebno obnoviti izgubljeni izvorni kod iz zastarelog assembly-ja. Pored toga, dotPeek omogućava praktično kretanje kroz dekompilirani kod, što ga čini jednim od idealnih alata za **analizu Xamarin algoritama.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Zahvaljujući sveobuhvatnom modelu dodataka i API-ju koji omogućava prilagođavanje alata vašim potrebama, .NET Reflector štedi vreme i pojednostavljuje razvoj. Pogledajmo mnoštvo usluga za reverzno inženjerstvo koje ovaj alat pruža:

- Omogućava uvid u tok podataka kroz biblioteku ili komponentu
- Omogućava uvid u implementaciju i upotrebu .NET jezika i okvira
- Pronalaži nedokumentovanu i neizloženu funkcionalnost kako biste bolje iskoristili korišćene API-je i tehnologije.
- Pronalaži zavisnosti i različite assembly-je
- Pronalazi tačnu lokaciju grešaka u vašem kodu, komponentama trećih strana i bibliotekama.
- Omogućava debugovanje izvornog koda celokupnog .NET koda s kojim radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy dodatak za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga instalirati direktno iz VSCode-a, nema potrebe da preuzimate git. Kliknite na **Extensions** i **potražite ILSpy**).\
Ako treba da **dekompilirate**, **izmenite** i ponovo **kompilirate**, možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegovu aktivno održavanu fork verziju, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Desni klik -> Modify Method** da biste nešto promenili unutar funkcije).

### DNSpy Logging

Da bi **DNSpy zapisivao određene informacije u datoteku**, možete koristiti ovaj isečak koda:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy otklanjanje grešaka

Da biste otklanjali greške u kodu pomoću DNSpy-ja, potrebno je da:

Najpre promenite **Assembly attributes** povezane sa **otklanjanjem grešaka**:

![DNSpy Logging - DNSpy otklanjanje grešaka: Najpre promenite Assembly attributes povezane sa otklanjanjem grešaka](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: I kliknite na compile](<../../images/image (314) (1).png>)

Zatim sačuvajte novu datoteku preko _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Zatim sačuvajte novu datoteku preko File Save module](<../../images/image (602).png>)

Ovo je neophodno jer će se, ako to ne uradite, tokom **izvršavanja** na kod primeniti nekoliko **optimizacija**, pa je moguće da se prilikom otklanjanja grešaka **tačka prekida nikada ne aktivira** ili da neke **promenljive ne postoje**.

Zatim, ako vašu .NET aplikaciju **pokreće** **IIS**, možete je **restartovati** pomoću:

```
iisreset /noforce
```

Zatim, da biste započeli debugovanje, zatvorite sve otvorene datoteke i na kartici **Debug** izaberite **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste započeli debugovanje, zatvorite sve otvorene datoteke i na kartici Debug izaberite Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste se povezali sa **IIS serverom** i kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste se povezali sa IIS serverom i kliknite na attach](<../../images/image (113).png>)

Sada kada debugujemo proces, zaustavite ga i učitajte sve module. Najpre kliknite na _Debug >> Break All_, a zatim na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, zaustavite ga i učitajte sve module. Najpre kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, zaustavite ga i učitajte sve module. Najpre kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u prozoru **Modules** i izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u prozoru Modules i izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom miša na bilo koji modul u **Assembly Explorer** i izaberite **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom miša na bilo koji modul u Assembly Explorer i izaberite Sort Assemblies](<../../images/image (339).png>)

## Java dekompajler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugovanje DLL-ova

### Korišćenje IDA-e

- **Učitajte rundll32** (64-bitna verzija je u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- Izaberite debugger **Windbg**
- Izaberite "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Podesite **parametre** izvršavanja tako što ćete navesti **putanju do DLL-a** i funkciju koju želite da pozovete:

![Debugging DLLs - Using IDA: Podesite parametre izvršavanja tako što ćete navesti putanju do DLL-a i funkciju koju želite da pozovete](<../../images/image (704).png>)

Kada pokrenete debugovanje, **izvršavanje će se zaustaviti pri učitavanju svakog DLL-a**. Dakle, kada rundll32 učita vaš DLL, izvršavanje će se zaustaviti.

Ovaj metod zaustavlja izvršavanje pri događajima učitavanja modula, ali je dolazak do entry point-a učitanog DLL-a manje direktan nego u x64dbg postupku ispod.

### Korišćenje x64dbg/x32dbg

- **Učitajte rundll32** (64-bitna verzija je u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- **Promenite Command Line** ( _File --> Change Command Line_ ) i navedite putanju do DLL-a i funkciju koju želite da pozovete, na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Otvorite _Options --> Settings_ i izaberite "**DLL Entry**".
- Zatim **pokrenite izvršavanje**. Debugger će se zaustaviti pri svakom dll main-u i u jednom trenutku će se **zaustaviti na entry point-u vašeg DLL-a**. Zatim samo pronađite mesta na koja želite da postavite breakpoint.

Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, možete videti **u kom ste kodu** tako što ćete pogledati **vrh prozora win64dbg-a**:

![Using IDA - Using x64dbg/x32dbg: Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, možete videti u kom ste kodu tako što ćete pogledati vrh prozora win64dbg-a](<../../images/image (842).png>)

Ovaj indikator potvrđuje da li je izvršavanje zaustavljeno unutar DLL-a koji želite da debugujete.

## GUI aplikacije / video-igre

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje mesta u memoriji pokrenute igre na kojima su sačuvane važne vrednosti, kao i za njihovu promenu. Više informacija:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je frontend / alat za reverse engineering za GNU Project Debugger (GDB), namenjen igrama. Međutim, može se koristiti za sve što je povezano sa reverse engineering-om.

[**Decompiler Explorer**](https://dogbolt.org/) je web frontend za nekoliko dekompajlera. Ovaj web servis omogućava poređenje rezultata različitih dekompajlera na malim izvršnim datotekama.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### Debugovanje shellcode-a pomoću blobrunner-a

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alocira **shellcode**, ispisuje njegovu **memorijsku adresu** i pauzira izvršavanje.\
Prikačite debugger, na primer IDA ili x64dbg, postavite breakpoint na ispisanu adresu i nastavite izvršavanje da biste debugovali shellcode.

Stranica GitHub releases sadrži zip datoteke sa kompajliranim izdanjima: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blago izmenjenu verziju Blobrunner-a možete pronaći na sledećem linku. Da biste je kompajlirali, **napravite C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod, pa ga izgradite**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugovanje shellcode-a pomoću jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je sličan alatu BlobRunner. Alocira shellcode i ulazi u beskonačnu petlju. Prikačite debugger, nastavite izvršavanje na **2–5 sekundi**, pauzirajte ga unutar te petlje, a zatim nastavite korak po korak do sledećeg poziva koji prenosi izvršavanje na alocirani shellcode.

![Debugger pauziran u beskonačnoj petlji alata jmp2it neposredno pre poziva alociranog shellcode-a](<../../images/image (509).png>)

Kompajliranu verziju alata [jmp2it možete preuzeti na stranici releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugovanje shellcode-a pomoću Cutter-a

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI za radare. Pomoću Cutter-a možete emulirati shellcode i dinamički ga pregledati.

Imajte na umu da Cutter omogućava izbor opcija „Open File“ i „Open Shellcode“. U mom slučaju, kada sam shellcode otvorio kao datoteku, dekompajlirao ga je ispravno, ali kada sam ga otvorio kao shellcode, nije:

![Cutter prikazuje različite rezultate analize kada se isti bajtovi otvore kao datoteka ili kao shellcode](<../../images/image (562).png>)

Da biste započeli emulaciju na željenom mestu, postavite bp na to mesto. Čini se da će Cutter automatski započeti emulaciju odatle:

![Postavljanje breakpoint-a na željeni ulaz u shellcode pre pokretanja emulacije u Cutter-u](<../../images/image (589).png>)

![Cutter emulator pauziran na izabranom breakpoint-u u shellcode-u](<../../images/image (387).png>)

Na primer, stek možete videti u hex dump-u:

![Prikaz steka emuliranog shellcode-a u Cutter-ovom hex dump-u](<../../images/image (186).png>)

### Deobfuskacija shellcode-a i pronalaženje pozvanih funkcija

Probajte [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Prikazaće vam, na primer, **koje funkcije** shellcode koristi i da li se **dekodira** u memoriji.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg takođe ima grafički pokretač u kom možete da izaberete željene opcije i izvršite shellcode

![Grafički pokretač scDbg-a za izbor opcija emulacije i praćenja shellcode-a](<../../images/image (258).png>)

Opcija **Create Dump** će sačuvati završni shellcode ako se on dinamički izmeni u memoriji (korisno za preuzimanje dekodiranog shellcode-a). **start offset** može biti koristan za pokretanje shellcode-a od određenog pomeraja. Opcija **Debug Shell** korisna je za otklanjanje grešaka u shellcode-u pomoću scDbg terminala (međutim, smatram da je za to bolja bilo koja od ranije objašnjenih opcija, jer ćete moći da koristite Ida ili x64dbg).

### Disasembliranje pomoću CyberChef-a

Otpremite datoteku sa shellcode-om kao ulaz i upotrebite sledeći recept da biste ga dekompilirali: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskacija MBA obfuscation-a

**Mixed Boolean-Arithmetic (MBA)** obfuscation skriva jednostavne izraze kao što je `x + y` iza formula koje kombinuju aritmetičke operatore (`+`, `-`, `*`) i bitovske operatore (`&`, `|`, `^`, `~`, pomeranja). Važno je da su ovi identiteti obično tačni samo pri **modularnoj aritmetici fiksne širine**, pa su prenosi i prekoračenja bitni:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ako pojednostavite izraz ove vrste pomoću generičkih alata za algebru, lako možete dobiti pogrešan rezultat jer semantika širine bita nije uzeta u obzir.<sup>[[1]](#references)</sup>

### Praktični radni tok

1. **Sačuvajte originalnu širinu bita** iz podignutog koda/IR izlaza dekompilatora (`8/16/32/64` bita).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
   - **Linearan**: ponderisani zbirovi bitovskih atoma
   - **Polulinearan**: linearan izraz uz konstantne maske, kao što je `x & 0xFF`
   - **Polinomski**: sadrži proizvode
   - **Mešovit**: proizvodi i bitovska logika su isprepleteni, često sa ponovljenim podizrazima
3. **Proverite svako predloženo prepisivanje** nasumičnim testiranjem ili SMT dokazom. Ako se ekvivalencija ne može dokazati, zadržite originalni izraz umesto da nagađate.

### Zaobiđite spljošteni kontrolni tok pomoću uskog izvršnog isečka

Često nije potrebno rekonstruisati ceo graf kontrolnog toka. Kod spljoštavanja kontrolnog toka, neprozirnih predikata, velikih dispečera ili koda sa mnogo MBA izraza, pratite reference od šifrovanih blokova podataka i izlaznih bafera do najmanje rutine koja ih transformiše. Zatim reprodukujte samo taj isečak toka podataka ili ga izvršite nezavisno; dispečer nije deo neophodnog rešenja ako se relevantno stanje može direktno inicijalizovati.<sup>[[7]](#references)</sup>

Praktični radni tok je:<sup>[[7]](#references)</sup>

1. Napravite popis izvršnih odeljaka i odeljaka sa podacima, relokacija i unakrsnih referenci. Izdvojite moguće tabele iz `.rodata`, čuvajući redosled bajtova i širinu elemenata.
2. Pronađite poslednju rutinu koja upisuje otvoreni tekst ili izlazni bafer. Zabeležite njene ulaze, referencirane tabele, uvezene pozive i neophodno globalno stanje.
3. Prenesite samo te operacije u Python model fiksne širine. Ako isečak i dalje zavisi od previše stanja, pozovite rutinu pomoću Unicorn-a, QEMU-a ili debagera i zakačite nevažne uvezene funkcije umesto da emulirate ceo program.
4. Potvrdite da izdvajanje zaista izvodi izlaz iz dostavljenog binarnog fajla: uklonite tihe rezervne mehanizme, pretražite ga u potrazi za ugrađenim odgovorima i pokrenite ga nad nepoznatim verzijama sa izmenjenim nizovima, ključevima, identifikatorima, rasporedima podataka i semenkama obfuskacije.

Korisne početne komande su:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Otkrijte MBA izraze koji su prikriveni kao konstante

Izraz nad bajtom koji naizgled zavisi od ulaza može u potpunosti da poništi njegov uticaj. Nakon izdvajanja tabela, izračunajte izraz za čitav 8-bitni domen; skup izlaza koji sadrži samo jednu vrednost dokazuje da je taj bajt konstanta, bez potrebe za rekonstrukcijom okolne mašine stanja.<sup>[[7]](#references)</sup>

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

Zadržite završnu masku jer originalno sabiranje ima prelivanje širine bajta. Za širi domen, pitajte SMT solver da li je `f(x1) != f(x2)` zadovoljivo za dva simbolička ulaza iste širine: `unsat` dokazuje invarijantnost, dok `sat` daje kontraprimer i znači da se ulaz ne može odbaciti.<sup>[[7]](#references)</sup>

#### Prepoznajte dekodiranje vezano za okruženje

Provere protiv analize ne moraju da izazovu grananje ili pad. Dekoder može da pomeša rezultat senzora u bit ključa, konstantu opaque-predicate-a ili stanje spljoštenog dispečera, da nastavi normalno i da u emulatoru proizvede uverljiv, ali netačan tekst. Zato nije dovoljno zakrpiti samo vidljive grane koje izazivaju grešku; pratite zavisnosti podataka od proba okruženja do stanja dekodera, uporedite isti isečak na autentičnom uređaju i emulatoru i testirajte kako forsiranje svakog rezultata senzora menja završni bafer.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktičan MBA pojednostavljivač za analizu malware-a i reverzno inženjerstvo zaštićenih binarnih fajlova. Klasifikuje izraz i prosleđuje ga specijalizovanim cevovodima umesto da na sve primenjuje jedan generički prolaz za prepisivanje.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evaluira izraz na Bulovim ulazima, izvodi potpis i istovremeno pokreće nekoliko metoda za oporavak, kao što su uparivanje obrazaca, ANF konverzija i interpolacija koeficijenata.
- **Semilinear MBA**: atomi maskirani konstantama ponovo se grade pomoću rekonstrukcije podeljene po bitovima, tako da maskirani regioni ostanu ispravni.
- **Polynomial/Mixed MBA**: proizvodi se razlažu na jezgra, a ponovljeni podizrazi mogu se izdvojiti u privremene promenljive pre pojednostavljivanja spoljne relacije.

Primer mešanog identiteta koji često vredi pokušati oporaviti:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Ovo se može svesti na:

```c
x * y
```

### Napomene o reverse engineeringu

- Prednost dajte pokretanju CoBRA nad **podignutim IR izrazima** ili izlazom dekompilatora, nakon što izdvojite tačan proračun.
- Eksplicitno koristite `--bitwidth` kada izraz potiče iz maskirane aritmetike ili uskih registara.
- Ako vam je potreban snažniji korak dokazivanja, pogledajte lokalne Z3 beleške ovde:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA se isporučuje i kao **dodatak za LLVM pass** (`libCobraPass.so`), što je korisno kada želite da normalizujete LLVM IR sa mnogo MBA operacija pre kasnijih faza analize.
- Nepodržane ostatke osetljive na prenos u mešovitim domenima treba smatrati signalom da zadržite originalni izraz i ručno analizirate putanju prenosa.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuscator zamenjuje programske operacije nizovima instrukcija zasnovanim na `mov` instrukciji i koristi obradu signala/izuzetaka da bi izmenio tok upravljanja. Detalji:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Za podržane binarne fajlove, [demovfuscator](https://github.com/kirschju/demovfuscator) može da deobfuskuje rezultat. Ima nekoliko zavisnosti.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

And [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako igrate **CTF, ovo zaobilazno rešenje za pronalaženje flag-a** može biti veoma korisno: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **ulaznu tačku**, pretražite funkcije po `::main`, kao u primeru:

![Pronalaženje Rust ulazne tačke u Ghidri pretragom naziva funkcija po dvostrukoj dvotački i reči main](<../../images/image (1080).png>)

U ovom slučaju, binarna datoteka se zvala authenticator, pa je prilično očigledno koja je glavna funkcija zanimljiva.\
Kada imate **nazive** pozvanih **funkcija**, potražite ih na **Internetu** da biste saznali više o njihovim **ulazima** i **izlazima**.

### Oporavak Rust stringova iz ELF firmware-a

U **Rust ELF** binarnim datotekama mnogi statički stringovi nisu referencirani pokazivačima koji se završavaju nulom, kao u C-u. Uobičajeni raspored `rustc` koristi **n-torku pokazivač/dužina** unutar **`.data.rel.ro`**, koja pokazuje na stvarni blok stringa smešten u **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

To znači da `strings` ili podrazumevana Ghidra analiza mogu spojiti susedne stringove ili potpuno propustiti unakrsne reference.<sup>[[3]](#references)</sup>

Brz tok rada:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Nabavite virtuelnu adresu i veličinu sekcije **`.rodata`**.
2. Prođite kroz **`.data.rel.ro`** reč po reč.
3. Svaku vrednost unutar opsega adresa `.rodata` tretirajte kao kandidata za pokazivač na string.
4. Sledeću reč tretirajte kao kandidatsku dužinu.
5. Primenite filtere za proveru ispravnosti (na primer, zadržite dužine između **4** i **100** bajtova).
6. Pročitajte tačno `length` bajtova iz `.rodata`, umesto da skenirate do `0x00`.

Minimalna logika ekstraktora:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Ovo je posebno korisno pri reverse engineering-u firmware-a, jer pronađeni Rust stringovi često otkrivaju **HTTP rute, RPC nazive, log poruke, assert-e, nazive fajlova, config ključeve, command handlere i logiku povezanu sa autentifikacijom**.

Ako Ghidra ne pronađe te stringove, pokrenite prilagođenu skriptu/plugin koji primenjuje istu heuristiku i kreira string podatke na referenciranim `.rodata` offsetima. Objavljeni alati `rust-strings` i `RustStrings.py` kompanije Pen Test Partners korisne su reference za prilagođavanje ove ideje drugim **veličinama reči, redosledima bajtova i rasporedima sekcija**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Za kompajlirane Delphi binarne fajlove možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako treba da radite reverse engineering Delphi binarnog fajla, predlažem da koristite IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pritisnite **Alt+F7** u IDA-i da učitate Python plugin, a zatim izaberite fajl plugina.

Ovaj plugin će izvršiti binarni fajl i dinamički razrešiti nazive funkcija na početku otklanjanja grešaka. Nakon pokretanja otklanjanja grešaka, ponovo pritisnite dugme Start (zeleno dugme ili f9) i breakpoint će se aktivirati na početku stvarnog koda.

Ako pritisnete dugme u grafičkoj aplikaciji, debugger može da se zaustavi u funkciji koju to dugme poziva.

## Golang

Ako treba da radite reverse engineering Golang binarnog fajla, predlažem da koristite IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pritisnite **Alt+F7** u IDA-i da učitate Python plugin, a zatim izaberite fajl plugina.

Ovo će razrešiti nazive funkcija.

## Kompajlirani Python

Na ovoj stranici možete pronaći kako da dođete do Python koda iz kompajliranog Python binarnog fajla ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ako dobijete **binarni fajl** GBA igre, možete koristiti različite alate za njeno **emuliranje** i **debugovanje**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite debug verziju_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

U [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_** ** možete videti kako da pritisnete Game Boy Advance **dugmad**

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Svaki **taster ima vrednost** koja ga identifikuje:

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

Dakle, u ovoj vrsti programa zanimljivo je **kako program obrađuje korisnički unos**. Na adresi **0x4000130** pronaći ćete često prisutnu funkciju: **KEYINPUT**.

![Ghidra prikaz GBA binarnog fajla koji upućuje na KEYINPUT na adresi 0x4000130](<../../images/image (447).png>)

Na prethodnoj slici možete videti da se funkcija poziva iz **FUN_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekih operacija inicijalizacije (koje nisu važne):

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

Poslednji if proverava da li se **`uVar4`** nalazi među **prethodnim tasterima** i nije trenutni taster, što znači da je dugme otpušteno (trenutni taster je sačuvan u **`uVar1`**).

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

- Prvo se poredi sa **vrednošću 4** (dugme **SELECT**): u izazovu ovo dugme briše ekran
- Zatim se vrednost poredi sa **8** (dugme **START**); u ovom izazovu ta putanja proverava da li je uneti kod validan.
  - U ovom slučaju, varijabla **`DAT_030000d8`** se poredi sa 0xf3 i, ako su vrednosti iste, izvršava se određeni kod.
- U svim ostalim slučajevima proverava se i uvećava brojač (`DAT_030000d4`).\
  Dok je brojač manji od 8, vrednosti pritisnutih dugmadi sabiraju se u `DAT_030000d8`.

Dakle, u ovom izazovu, kada znate vrednosti dugmadi, trebalo je da **pritisnete kombinaciju kraću od 8 dugmadi čiji zbir iznosi 0xf3.**

**Referenca za ovaj tutorijal:** [arhivirani opis rešenja izazova Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursevi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Deobfuskacija binarnih fajlova)

## References

- [1] [Pojednostavljivanje MBA obfuskacije pomoću CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repozitorijum](https://github.com/trailofbits/CoBRA)
- [3] [Dekodiranje Rust stringova - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorijal (arhiviran)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Sprečavanje AI-potpomognutog reverse engineeringa — ili bar pokušaj](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
