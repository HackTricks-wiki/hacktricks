# Alati za reversing i osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## Alati za reversing zasnovani na ImGui

Softver:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Debugovanje Windows kernela

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Online:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) za **dekompilaciju** iz wasm (binarni) u wat (čitljiv tekst)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) za **kompilaciju** iz wat u wasm
- Možete isprobati i [web-wasmdec](https://wwwg.github.io/web-wasmdec/) za dekompilaciju.

Softver:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Keširani bytecode za Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtuelizovani payload-i i prilagođene VM mašine

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je decompiler koji **dekompajlira i analizira više formata**, uključujući **biblioteke** (.dll), **Windows metadata fajlove** (.winmd) i **izvršne fajlove** (.exe). Nakon dekompilacije, assembly se može sačuvati kao Visual Studio projekat (.csproj).

Prednost je u tome što, ako je potrebno obnoviti izgubljeni izvorni kod iz zastarelog assembly-ja, ovaj postupak može da uštedi vreme. Pored toga, dotPeek omogućava praktičnu navigaciju kroz dekompilirani kod, što ga čini jednim od savršenih alata za **analizu Xamarin algoritama.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Uz sveobuhvatan model dodataka i API koji proširuje alat tako da odgovara vašim potrebama, .NET Reflector štedi vreme i pojednostavljuje razvoj. Pogledajmo mnoštvo usluga za reverse engineering koje ovaj alat pruža:

- Daje uvid u tok podataka kroz biblioteku ili komponentu
- Daje uvid u implementaciju i upotrebu .NET jezika i okvira
- Pronalazi nedokumentiranu i neizloženu funkcionalnost kako biste bolje iskoristili korišćene API-je i tehnologije.
- Pronalazi zavisnosti i različite assembly-je
- Pronalazi tačnu lokaciju grešaka u vašem kodu, komponentama trećih strana i bibliotekama.
- Omogućava debugovanje izvornog koda za sav .NET kod s kojim radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) i [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy dodatak za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga instalirati direktno iz VSCode-a, nema potrebe da preuzimate git. Kliknite na **Extensions** i **potražite ILSpy**).\
Ako treba da **dekompajlirate**, **izmenite** i ponovo **kompajlirate**, možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegov aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknite desnim tasterom -> Modify Method** da biste nešto izmenili unutar funkcije).

### DNSpy Logging

Da biste podesili da **DNSpy beleži određene informacije u fajl**, možete koristiti ovaj isečak:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Da biste debugovali kod pomoću DNSpy-ja, potrebno je da:

Prvo promenite **Assembly attributes** koji se odnose na **debugging**:

![DNSpy Logging - DNSpy Debugging: Prvo promenite Assembly attributes koji se odnose na debugging](<../../images/image (973).png>)

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

Ovo je neophodno jer će se, ako to ne uradite, tokom **vremena izvršavanja** na kod primeniti nekoliko **optimizacija**, pa je moguće da se pri debagovanju **tačka prekida nikada ne aktivira** ili da neke **promenljive ne postoje**.

Zatim, ako vašu .NET aplikaciju **pokreće** **IIS**, možete je **ponovo pokrenuti** pomoću:

```
iisreset /noforce
```

Zatim, da biste počeli debugging, zatvorite sve otvorene datoteke, pa na kartici **Debug** izaberite **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste počeli debugging, zatvorite sve otvorene datoteke, pa na kartici Debug izaberite Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste se povezali sa **IIS serverom**, pa kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste se povezali sa IIS serverom, pa kliknite na attach](<../../images/image (113).png>)

Sada kada debugujemo proces, treba da ga zaustavimo i učitamo sve module. Najpre kliknite na _Debug >> Break All_, a zatim na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, treba da ga zaustavimo i učitamo sve module. Najpre kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, treba da ga zaustavimo i učitamo sve module. Najpre kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u prozoru **Modules**, pa izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u prozoru Modules, pa izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom miša na bilo koji modul u prozoru **Assembly Explorer**, pa izaberite **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom miša na bilo koji modul u prozoru Assembly Explorer, pa izaberite Sort Assemblies](<../../images/image (339).png>)

## Java dekompajler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLL-ova

### Korišćenje IDA-e

- **Učitajte rundll32** (64-bitna verzija je u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- Izaberite debugger **Windbg**
- Izaberite "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Podesite **parametre** izvršavanja tako što ćete navesti **putanju do DLL-a** i funkciju koju želite da pozovete:

![Debugging DLLs - Using IDA: Podesite parametre izvršavanja tako što ćete navesti putanju do DLL-a i funkciju koju želite da pozovete](<../../images/image (704).png>)

Kada počnete debugging, **izvršavanje će se zaustaviti pri učitavanju svake DLL datoteke**. Zatim, kada rundll32 učita vaš DLL, izvršavanje će se zaustaviti.

Ovaj metod zaustavlja izvršavanje pri događajima učitavanja modula, ali dolazak do entry point-a učitanog DLL-a nije tako jednostavan kao u x64dbg postupku u nastavku.

### Korišćenje x64dbg/x32dbg

- **Učitajte rundll32** (64-bitna verzija je u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- **Promenite Command Line** ( _File --> Change Command Line_ ) i unesite putanju do DLL-a i funkciju koju želite da pozovete, na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- U _Options --> Settings_ izaberite "**DLL Entry**".
- Zatim **pokrenite izvršavanje**. Debugger će se zaustaviti pri svakom dll main-u, a u jednom trenutku će se **zaustaviti na entry point-u vašeg DLL-a**. Odatle samo potražite mesta na koja želite da postavite breakpoint.

Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, možete da vidite **u kom se kodu nalazite** pri **vrhu prozora win64dbg-a**:

![Using IDA - Using x64dbg/x32dbg: Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, možete da vidite u kom se kodu nalazite pri vrhu prozora win64dbg-a](<../../images/image (842).png>)

Ovaj indikator potvrđuje da se izvršavanje zaustavilo unutar DLL-a koji želite da debugujete.

## GUI aplikacije / video-igre

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje važnih vrednosti sačuvanih u memoriji pokrenute igre i njihovu izmenu. Više informacija:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end/reverse engineering alat za GNU Project Debugger (GDB), namenjen igrama. Međutim, može da se koristi za bilo šta u vezi sa reverse engineering-om.

[**Decompiler Explorer**](https://dogbolt.org/) je web front-end za više dekompajlera. Ova web usluga vam omogućava da uporedite izlaz različitih dekompajlera nad manjim izvršnim datotekama.

## ARM i MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### Debugging shellcode-a pomoću blobrunner-a

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alocira **shellcode**, ispisuje njegovu **memorijsku adresu** i pauzira izvršavanje.\
Prikačite debugger, kao što su IDA ili x64dbg, postavite breakpoint na ispisanu adresu, pa nastavite izvršavanje da biste debugovali shellcode.

GitHub stranica sa izdanjima sadrži ZIP datoteke sa kompajliranim izdanjima: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blago izmenjenu verziju Blobrunner-a možete pronaći na sledećem linku. Da biste je kompajlirali, **napravite C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod, pa ga izgradite**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging shellcode-a pomoću jmp2it-a

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je sličan BlobRunner-u. Alocira shellcode i ulazi u beskonačnu petlju. Prikačite debugger, nastavite izvršavanje na **2–5 sekundi**, pauzirajte unutar te petlje i napravite korak do sledećeg poziva koji prenosi izvršavanje na alocirani shellcode.

![Debugger pauziran u beskonačnoj petlji jmp2it-a, neposredno pre poziva alociranog shellcode-a](<../../images/image (509).png>)

Kompajliranu verziju možete preuzeti sa [stranice izdanja jmp2it-a](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode-a pomoću Cutter-a

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI za radare. Cutter-om možete da emulirate shellcode i dinamički ga pregledate.

Imajte na umu da Cutter omogućava opcije „Open File“ i „Open Shellcode“. U mom slučaju, kada sam otvorio shellcode kao datoteku, ispravno ga je dekompajlirao, ali kada sam ga otvorio kao shellcode, nije:

![Cutter prikazuje različite rezultate analize kada se isti bajtovi otvore kao datoteka ili kao shellcode](<../../images/image (562).png>)

Da biste pokrenuli emulaciju na željenom mestu, postavite bp na to mesto. Cutter će, izgleda, automatski pokrenuti emulaciju odatle:

![Postavljanje breakpoint-a na željeni ulaz shellcode-a pre pokretanja Cutter emulacije](<../../images/image (589).png>)

![Cutter emulator pauziran na izabranom breakpoint-u shellcode-a](<../../images/image (387).png>)

Na primer, stek možete da vidite unutar hex dump-a:

![Prikaz steka emuliranog shellcode-a u Cutter-ovom hex dump-u](<../../images/image (186).png>)

### Deobfuskacija shellcode-a i pronalaženje pozvanih funkcija

Probajte [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Pokazaće vam, na primer, **koje funkcije** shellcode koristi i da li se **dekodira** u memoriji.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg ima i grafički pokretač u kom možete da izaberete željene opcije i izvršite shellcode

![scDbg grafički pokretač za izbor opcija za emulaciju i praćenje shellcode-a](<../../images/image (258).png>)

Opcija **Create Dump** će sačuvati konačni shellcode ako se u memoriji dinamički izvrše bilo kakve izmene shellcode-a (korisno za preuzimanje dekodiranog shellcode-a). Opcija **start offset** može biti korisna za pokretanje shellcode-a od određenog pomeraja. Opcija **Debug Shell** korisna je za debagovanje shellcode-a pomoću scDbg terminala (međutim, za ovu namenu su mi bolje bilo koje od prethodno objašnjenih opcija, jer ćete moći da koristite Ida ili x64dbg).

### Disasembliranje pomoću CyberChef-a

Otpremite datoteku shellcode-a kao ulaz i upotrebite sledeći recept da biste ga dekompilirali: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Uklanjanje MBA obfuskacije

**Mixed Boolean-Arithmetic (MBA)** obfuskacija skriva jednostavne izraze kao što je `x + y` iza formula koje kombinuju aritmetičke (`+`, `-`, `*`) i bitovske operatore (`&`, `|`, `^`, `~`, pomeranja). Važno je da su ovi identiteti obično tačni samo pri **modularnoj aritmetici fiksne širine**, tako da su prenosi i prekoračenja bitni:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ako pojednostavite ovakvu vrstu izraza pomoću generičkih alata za algebru, lako možete dobiti pogrešan rezultat jer semantika širine bitova nije uzeta u obzir.<sup>[[1]](#references)</sup>

### Praktični postupak

1. **Zadržite originalnu širinu bitova** iz podignutog koda/IR-a/izlaza dekompilatora (`8/16/32/64` bita).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
   - **Linearan**: ponderisani zbirovi bitovskih atoma
   - **Semilinearan**: linearni izraz plus konstantne maske kao što je `x & 0xFF`
   - **Polinomski**: pojavljuju se proizvodi
   - **Mešovit**: proizvodi i bitovska logika su isprepletani, često uz ponovljene podizraze
3. **Proverite svako predloženo prepisivanje** nasumičnim testiranjem ili SMT dokazom. Ako se ekvivalencija ne može dokazati, zadržite originalni izraz umesto da nagađate.

### Zaobiđite spljošteni tok upravljanja pomoću uskog isečka izvršavanja

Često nema potrebe za rekonstrukcijom kompletnog grafa toka upravljanja. Kod control-flow flattening-a, neprozirnih predikata, velikih dispečera ili koda sa mnogo MBA izraza, pratite reference od šifrovanih blokova i izlaznih bafera do najmanje rutine koja ih transformiše. Zatim reprodukujte samo taj isečak toka podataka ili ga izvršite nezavisno; dispečer nije deo potrebnog rešenja ako se relevantno stanje može direktno inicijalizovati.<sup>[[7]](#references)</sup>

Praktični postupak je:<sup>[[7]](#references)</sup>

1. Popišite izvršne i podatkovne sekcije, relokacije i unakrsne reference. Izbacite kandidate za tabele iz `.rodata`, uz očuvanje redosleda bajtova i širine elemenata.
2. Identifikujte poslednju rutinu koja upisuje običan tekst ili izlazni bafer. Zabeležite njene ulaze, referencirane tabele, uvezene pozive i potrebno globalno stanje.
3. Prenesite samo te operacije u Python model fiksne širine. Ako isečak i dalje zavisi od previše stanja, pozovite rutinu pomoću Unicorn-a, QEMU-a ili debagera i zakačite nebitne uvezene funkcije umesto da emuliрате ceo program.
4. Proverite da ekstraktor zaista izvodi svoj izlaz iz dostavljenog binarnog fajla: uklonite tihe rezervne mehanizme, pretražite ga u potrazi za ugrađenim odgovorima i testirajte ga na nepoznatim verzijama sa izmenjenim stringovima, ključevima, identifikatorima, rasporedima i seed-ovima obfuskacije.

Korisne početne komande su:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Prepoznajte MBA izraze koji prikrivaju konstante

Bajtni izraz koji naizgled zavisi od ulaza može u potpunosti da poništi uticaj ulaza. Nakon izdvajanja njegovih tabela, izračunajte vrednost izraza za ceo 8-bitni domen; skup izlaznih vrednosti koji sadrži samo jedan element dokazuje da je taj bajt konstanta, bez potrebe da se rekonstruiše okolna mašina stanja.<sup>[[7]](#references)</sup>

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

Zadržite završnu masku jer originalno sabiranje ima prelivanje pri širini bajta. Za širi domen, pitajte SMT solver da li je `f(x1) != f(x2)` zadovoljivo za dva simbolička ulaza iste širine: `unsat` dokazuje invarijantnost, dok `sat` daje kontraprimer i znači da se ulaz ne može odbaciti.<sup>[[7]](#references)</sup>

#### Prepoznajte dekodiranje vezano za okruženje

Provere protiv analize ne moraju da granaju tok izvršavanja niti da izazovu pad. Dekoder može da ugradi rezultat senzora u bit ključa, konstantu opaque-predicate-a ili stanje flattenovanog dispečera, da nastavi normalno i proizvede uverljiv, ali netačan otvoreni tekst u emulatoru. Zato nije dovoljno zakrpiti samo vidljive grane koje izazivaju grešku; pratite zavisnosti podataka od sondi okruženja do stanja dekodera, uporedite isti isečak na autentičnom uređaju i u emulatoru i proverite kako forsiranje svakog rezultata senzora menja završni bafer.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktičan MBA simplifikator za analizu malware-a i reverzni inženjering zaštićenih binarnih fajlova. Klasifikuje izraz i usmerava ga kroz specijalizovane pipeline-ove, umesto da na sve primenjuje jedan generički prolaz za prepisivanje.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evaluira izraz na Boolean ulazima, izvodi potpis i istovremeno pokreće nekoliko metoda za oporavak, kao što su uparivanje obrazaca, ANF konverzija i interpolacija koeficijenata.
- **Semilinear MBA**: atomi maskirani konstantama ponovo se sastavljaju rekonstrukcijom podeljenom po bitovima, tako da maskirani regioni ostanu ispravni.
- **Polynomial/Mixed MBA**: proizvodi se razlažu na jezgra, a ponovljeni podizrazi mogu se izdvojiti u privremene promenljive pre pojednostavljivanja spoljne relacije.

Primer mešovitog identiteta koji često vredi pokušati oporaviti:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Ovo se može svesti na:

```c
x * y
```

### Reversing napomene

- Prednost dajte pokretanju CoBRA nad **lifted IR izrazima** ili izlazom dekompilatora, nakon što izdvojite tačan proračun.
- Eksplicitno koristite `--bitwidth` kada izraz potiče iz maskirane aritmetike ili registara uže širine.
- Ako vam je potreban snažniji korak dokazivanja, pogledajte lokalne Z3 napomene ovde:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA se isporučuje i kao **LLVM pass plugin** (`libCobraPass.so`), što je korisno kada želite da normalizujete LLVM IR sa mnogo MBA izraza pre kasnijih analiza.
- Nepodržane mešovite ostatke koji zavise od prenosa tretirajte kao signal da zadržite originalni izraz i ručno analizirate put prenosa.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuscator zamenjuje programske operacije nizovima instrukcija zasnovanim na `mov` i koristi obradu signala/izuzetaka za izmenu toka izvršavanja. Više detalja:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Za podržane binarne fajlove, [demovfuscator](https://github.com/kirschju/demovfuscator) može da deobfuscate-uje rezultat. Ima nekoliko zavisnosti.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

I [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako igrate **CTF, ovo zaobilazno rešenje za pronalaženje flag-a** može biti veoma korisno: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **entry point**, pretražite funkcije pomoću `::main`, kao u primeru:

![Pronalaženje Rust entry point-a u Ghidra-i pretragom naziva funkcija za double-colon main](<../../images/image (1080).png>)

U ovom slučaju, binarni fajl se zvao authenticator, tako da je prilično očigledno koja je glavna funkcija od interesa.\
Kada imate **nazive** pozivanih **funkcija**, potražite ih na **Internetu** da biste saznali više o njihovim **ulazima** i **izlazima**.

### Oporavak Rust stringova iz ELF firmware-a

U **Rust ELF** binarnim fajlovima, mnogi statički stringovi nisu referencirani kao C-style NUL-terminated pokazivači. Čest `rustc` raspored koristi **torku pokazivač/dužina** unutar **`.data.rel.ro`** koja pokazuje na stvarni string blob sačuvan u **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

To znači da `strings` ili podrazumevana Ghidra analiza mogu spojiti susedne stringove ili potpuno propustiti unakrsne reference.<sup>[[3]](#references)</sup>

Brz tok rada:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pronađite virtuelnu adresu i veličinu sekcije **`.rodata`**.
2. Prođite kroz **`.data.rel.ro`** reč po reč.
3. Svaku vrednost unutar adresnog opsega `.rodata` tretirajte kao kandidata za pokazivač na string.
4. Sledeću reč tretirajte kao kandidata za dužinu.
5. Primenite razumne filtere (na primer, zadržite dužine između **4** i **100** bajtova).
6. Pročitajte tačno `length` bajtova iz `.rodata`, umesto da skenirate do `0x00`.

Minimalna logika za izdvajanje:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Ovo je posebno korisno pri reverse engineering-u firmware-a, jer pronađeni Rust stringovi često otkrivaju **HTTP rute, RPC nazive, log poruke, asercije, imena datoteka, konfiguracione ključeve, obrađivače komandi i logiku povezanu sa autentifikacijom**.

Ako Ghidra ne pronađe te stringove, pokrenite prilagođenu skriptu/dodatak koji primenjuje istu heuristiku i kreira podatke stringova na referenciranim `.rodata` pomerajima. Objavljeni alati `rust-strings` i `RustStrings.py` kompanije Pen Test Partners korisni su kao reference za prilagođavanje ideje drugim **veličinama reči, redosledima bajtova i rasporedima sekcija**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Za binarne fajlove kompajlirane za Delphi možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako treba da radite reverse engineering Delphi binarnog fajla, preporučujem IDA dodatak [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pritisnite **Alt+F7** u IDA-i da učitate Python dodatak, a zatim izaberite datoteku dodatka.

Ovaj dodatak će izvršiti binarni fajl i dinamički razrešiti nazive funkcija na početku otklanjanja grešaka. Nakon pokretanja otklanjanja grešaka, ponovo pritisnite dugme Start (zeleno dugme ili f9) i tačka prekida će se aktivirati na početku stvarnog koda.

Ako pritisnete dugme u grafičkoj aplikaciji, debugger može da se zaustavi u funkciji koju je to dugme pozvalo.

## Golang

Za uobičajene Go binarne fajlove, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) može da pronađe runtime strukture i poboljša nazive funkcija u IDA-i. Učitajte njegov Python dodatak pomoću **Alt+F7**.

### Oporavak metapodataka bez tabele simbola

I dalje su potrebni runtime metapodaci u ogoljenoj Go izvršnoj datoteci kako bi se programski brojači povezali sa funkcijama. [GoReSym](https://github.com/mandiant/GoReSym) pronalazi i analizira strukture kao što su `pclntab` i `moduledata`, koristeći kod izveden iz Go runtime-a. Tako se mogu oporaviti granice funkcija, nazivi, izvorne putanje, tipovi i detalji o izgradnji bez oslanjanja na konvencionalnu tabelu simbola.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuskator može da ostavi te strukture upotrebljivim, a da zameni oporavljena imena. Garble, na primer, hešira identifikatore i putanje paketa i uklanja informacije o build-u, modulima i debugovanju.<sup>[[12]](#references)</sup> Obfuskirani token paketa mora da ostane dosledan u funkcijama iz tog paketa. Grupisati funkcije prema tokenu koji se ponavlja, zaključiti o kom je paketu reč na osnovu njegovih poziva, stringova i API-ja, a zatim tu oznaku paketa preneti na celu grupu.<sup>[[13]](#references)</sup>

### Oporavite Garble nazive pomoću GoResolver

[GoResolver](https://github.com/volexity/GoResolver) objedinjuje izdvajanje runtime simbola, generisanje čistih referenci i poklapanje grafova toka kontrole (CFG). Koristite sledeći redosled:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifikujte verziju kompajlera.** Najpre proverite `BuildInfo` i ugrađene stringove verzije. Ako ih je obfuskator uklonio, uporedite delove Go runtime-a iz binarne datoteke sa referentnim runtime-ovima za poznate verzije. U testovima kompanije Volexity, oko `2%` runtime-a bilo je dovoljno za razlikovanje glavnih verzija Go-a. Tretirajte ovo kao empirijsku optimizaciju, a ne kao univerzalni prag.<sup>[[13]](#references)</sup>
2. **Pripremite odgovarajuće reference.** Generišite čiste binarne datoteke za identifikovanu verziju Go-a, ciljnu arhitekturu i verovatne biblioteke. Podudaranje toolchain-a smanjuje razlike u CFG-u koje stvara kompajler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Uporedite funkcije.** GoGrapher uparuje CFG-ove funkcija i daje normalizovane ocene od `0.0` do `1.0`. Uparivanje osnovnih blokova zasniva se na ponderisanom poređenju sličnih instrukcija. Poklapanja sa visokim stepenom pouzdanosti povezuju nasumično imenovane funkcije sa čistom implementacijom. Slabija poklapanja i dalje mogu da identifikuju paket ili modul.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Proverite i uvezite.** Potvrdite predložena imena na osnovu odnosa poziva, konstanti, stringova i sporednih efekata, a zatim uvezite JSON izveštaj pomoću GoResolver dodatka za IDA ili Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instalirajte toolchain i pokrenite objedinjeni alat za izdvajanje i uparivanje grafova:<sup>[[10]](#references)</sup>

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

Podrazumevani prag značajnog poklapanja je `0.9`. Prekidači `--extract` i `--graph` mogu da izdvoje bilo koju fazu, dok se podrazumevano izvršavaju obe, jer se oporavljeni metapodaci izvršavanja i dokazi iz CFG-a međusobno dopunjuju.<sup>[[10]](#references)</sup> CFG skorovi su heuristički: inlining, build zastavice, arhitektura i razlike u verzijama biblioteka mogu da promene oblik grafa, zato sačuvajte nerešene funkcije umesto da im dodeljujete nazive sa niskim nivoom pouzdanosti.<sup>[[13]](#references)</sup>

## Kompajlirani Python

Na ovoj stranici možete pronaći kako da dobijete Python kod iz ELF/EXE binarne datoteke kompajlirane iz Python koda:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ako dobijete **binary** igre za GBA, možete koristiti različite alate da biste je **emulirali** i **debugovali**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite verziju za debugovanje_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

U programu [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_** ** možete videti kako se pritiskaju dugmad na Game Boy Advance konzoli.

![Konfiguracija kontrola u programu no$gba koja prikazuje mapiranje dugmadi za Game Boy Advance](<../../images/image (581).png>)

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

Dakle, u ovoj vrsti programa zanimljivo je **kako program obrađuje korisnički unos**. Na adresi **0x4000130** pronaći ćete uobičajeno pronađenu funkciju: **KEYINPUT**.

![Ghidra prikaz GBA binarne datoteke koja upućuje na KEYINPUT na adresi 0x4000130](<../../images/image (447).png>)

Na prethodnoj slici možete videti da se funkcija poziva iz **FUN_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekoliko početnih operacija (koje nisu važne):

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

Poslednji if proverava da li se **`uVar4`** nalazi u **prethodnom skupu tastera** i da li nije trenutni taster, što znači da je dugme otpušteno (trenutni taster se čuva u **`uVar1`**).

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
- Zatim se vrednost upoređuje sa **8** (dugme **START**); u ovom izazovu se tom granom proverava da li je uneti kod važeći.
  - U tom slučaju se varijabla **`DAT_030000d8`** upoređuje sa 0xf3 i, ako su vrednosti jednake, izvršava se određeni kod.
- U svim ostalim slučajevima proverava se i uvećava brojač (`DAT_030000d4`).\
  Dok je brojač manji od 8, vrednosti pritisnutih dugmadi sabiraju se u `DAT_030000d8`.

Dakle, u ovom izazovu, znajući vrednosti dugmadi, trebalo je da **pritisnete kombinaciju kraću od 8 dugmadi čiji je zbir 0xf3.**

**Referenca za ovaj vodič:** [arhivirani prikaz rešenja za Nostalgia izazov](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursevi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (uklanjanje obfuskacije iz binarnih datoteka)

## References

- [1] [Pojednostavljivanje MBA obfuskacije pomoću CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [CoBRA repozitorijum kompanije Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Dekodiranje Rust stringova - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - Rust stringovi](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - vodič za reverzno inženjerstvo za GBA (arhiviran)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Pobijanje reverznog inženjerstva potpomognutog veštačkom inteligencijom ili barem pokušaj toga](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Pristup poređenju grafova toka kontrole zasnovan na uparivanju osnovnih blokova](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mehanizam obfuskacije alata Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Korišćenje sličnosti grafova toka kontrole za automatsko uklanjanje obfuskacije iz Golang binarnih datoteka](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
