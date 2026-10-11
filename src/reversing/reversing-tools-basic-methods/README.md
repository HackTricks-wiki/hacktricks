# Alati za reverse engineering i osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## ImGui alati za reverse engineering

Softver:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Debugging Windows kernela

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Na mreži:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) da **decompile**-ujete wasm (binarni format) u wat (čitljiv tekst)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) da **compile**-ujete wat u wasm
- Za dekompilaciju možete isprobati i [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Softver:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 keširani bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je decompiler koji **decompile**-uje i ispituje više formata, uključujući **biblioteke** (.dll), **datoteke Windows metapodataka** (.winmd) i **izvršne datoteke** (.exe). Nakon dekompilacije, assembly se može sačuvati kao Visual Studio projekat (.csproj).

Prednost je u tome što ova radnja može uštedeti vreme ako je izgubljeni izvorni kod potrebno obnoviti iz zastarelog assembly-ja. Pored toga, dotPeek omogućava praktičnu navigaciju kroz dekompilovani kod, što ga čini jednim od idealnih alata za **analizu Xamarin algoritama.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Uz sveobuhvatan model dodataka i API koji omogućava prilagođavanje alata vašim potrebama, .NET Reflector štedi vreme i pojednostavljuje razvoj. Pogledajmo brojne usluge reverse engineering-a koje ovaj alat pruža:

- Omogućava uvid u tok podataka kroz biblioteku ili komponentu
- Omogućava uvid u implementaciju i upotrebu .NET jezika i okvira
- Pronalazi nedokumentirane i neizložene funkcionalnosti kako biste bolje iskoristili korišćene API-je i tehnologije.
- Pronalazi zavisnosti i različite assembly-je
- Pronalazi tačnu lokaciju grešaka u vašem kodu, komponentama trećih strana i bibliotekama.
- Omogućava debugging izvornog koda za sav .NET kod sa kojim radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy dodatak za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga instalirati direktno iz VSCode-a; git nije potrebno preuzimati. Kliknite na **Extensions** i **potražite ILSpy**).\
Ako želite da **decompile**-ujete, **izmenite** i ponovo **compile**-ujete, možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegov aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Klik desnim tasterom -> Modify Method** da biste nešto promenili unutar funkcije).

### DNSpy logovanje

Da bi **DNSpy beležio neke informacije u datoteku**, možete koristiti ovaj isečak koda:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy debagovanje

Da biste debagovali kod pomoću DNSpy-ja, potrebno je da:

Prvo promenite **Assembly atribute** povezane sa **debagovanjem**:

![DNSpy Logging - DNSpy debagovanje: Prvo promenite Assembly atribute povezane sa debagovanjem](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Zatim sačuvajte novu datoteku preko _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Ovo je neophodno jer će se, ako to ne uradite, tokom **runtime**-a na kod primeniti nekoliko **optimizacija**, pa je moguće da tokom debugovanja **tačka prekida nikad ne bude dostignuta** ili da neke **promenljive ne postoje**.

Zatim, ako vašu .NET aplikaciju **pokreće** **IIS**, možete da je **restartujete** pomoću:

```
iisreset /noforce
```

Zatim, da biste započeli debugovanje, zatvorite sve otvorene datoteke i na **Debug Tab** izaberite **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste započeli debugovanje, zatvorite sve otvorene datoteke i na kartici Debug izaberite Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste se povezali sa **IIS serverom** i kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste se povezali sa IIS serverom i kliknite na attach](<../../images/image (113).png>)

Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na _Debug >> Break All_, a zatim na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u odeljku **Modules** i izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u odeljku Modules i izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom miša na bilo koji modul u **Assembly Explorer** i kliknite na **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom miša na bilo koji modul u Assembly Explorer i kliknite na Sort Assemblies](<../../images/image (339).png>)

## Java dekompajler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugovanje DLL-ova

### Korišćenje IDA

- **Učitajte rundll32** (64-bitna verzija se nalazi na C:\Windows\System32\rundll32.exe, a 32-bitna na C:\Windows\SysWOW64\rundll32.exe)
- Izaberite debugger **Windbg**
- Izaberite "**Suspend on library load/unload**"

![Debugovanje DLL-ova - Korišćenje IDA: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Podesite **parametre** izvršavanja tako što ćete navesti **putanju do DLL-a** i funkciju koju želite da pozovete:

![Debugovanje DLL-ova - Korišćenje IDA: Podesite parametre izvršavanja tako što ćete navesti putanju do DLL-a i funkciju koju želite da pozovete](<../../images/image (704).png>)

Kada započnete debugovanje, **izvršavanje će se zaustaviti svaki put kada se učita DLL**. Dakle, kada rundll32 učita vaš DLL, izvršavanje će se zaustaviti.

Ovaj metod zaustavlja izvršavanje pri događajima učitavanja modula, ali je dolazak do ulazne tačke učitanog DLL-a manje direktan nego u x64dbg postupku ispod.

### Korišćenje x64dbg/x32dbg

- **Učitajte rundll32** (64-bitna verzija se nalazi na C:\Windows\System32\rundll32.exe, a 32-bitna na C:\Windows\SysWOW64\rundll32.exe)
- **Promenite komandnu liniju** ( _File --> Change Command Line_ ) i navedite putanju do DLL-a i funkciju koju želite da pozovete, na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Promenite _Options --> Settings_ i izaberite "**DLL Entry**".
- Zatim **pokrenite izvršavanje**. Debugger će se zaustavljati na svakoj dll main funkciji; u jednom trenutku će se **zaustaviti na ulaznoj tački vašeg DLL-a**. Odatle samo pronađite mesta na koja želite da postavite breakpoint.

Imajte na umu da kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg, možete da vidite **u kom ste kodu** tako što ćete pogledati **vrh prozora win64dbg**:

![Korišćenje IDA - Korišćenje x64dbg/x32dbg: Imajte na umu da kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg, možete da vidite u kom ste kodu tako što ćete pogledati vrh prozora win64dbg](<../../images/image (842).png>)

Ovaj indikator potvrđuje da je izvršavanje zaustavljeno unutar DLL-a koji želite da debugujete.

## GUI aplikacije / videoigre

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje mesta u memoriji pokrenute igre na kojima se čuvaju važne vrednosti i njihovu izmenu. Više informacija:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end/reverse engineering alat za GNU Project Debugger (GDB), namenjen igrama. Međutim, može se koristiti za bilo šta povezano sa reverse engineeringom.

[**Decompiler Explorer**](https://dogbolt.org/) je web front-end za više dekompajlera. Ovaj web servis omogućava poređenje izlaza različitih dekompajlera na malim izvršnim datotekama.

## ARM i MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### Debugovanje shellcode-a pomoću BlobRunner-a

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alocira **shellcode**, ispisuje njegovu **memorijsku adresu** i pauzira izvršavanje.\
Povežite debugger, kao što su IDA ili x64dbg, postavite breakpoint na ispisanu adresu i nastavite izvršavanje da biste debugovali shellcode.

Na GitHub stranici izdanja nalaze se zip datoteke sa kompajliranim izdanjima: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blago izmenjenu verziju Blobrunner-a možete pronaći na sledećem linku. Da biste je kompajlirali, **napravite C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod, pa ga izgradite**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugovanje shellcode-a pomoću jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je sličan BlobRunner-u. Alocira shellcode i ulazi u beskonačnu petlju. Povežite debugger, nastavite izvršavanje **2–5 sekundi**, pauzirajte unutar te petlje i pređite na sledeći poziv koji prenosi izvršavanje na alocirani shellcode.

![Debugger pauziran u beskonačnoj petlji jmp2it-a, neposredno pre poziva alociranog shellcode-a](<../../images/image (509).png>)

Kompajliranu verziju programa [jmp2it možete preuzeti sa stranice izdanja](https://github.com/adamkramer/jmp2it/releases/).

### Debugovanje shellcode-a pomoću Cutter-a

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI za radare. Pomoću Cutter-a možete emulirati shellcode i dinamički ga pregledati.

Imajte na umu da Cutter omogućava opcije „Open File“ i „Open Shellcode“. U mom slučaju, kada sam otvorio shellcode kao datoteku, on ga je ispravno dekompilirao, ali kada sam ga otvorio kao shellcode, nije:

![Cutter prikazuje različite rezultate analize kada se isti bajtovi otvore kao datoteka ili kao shellcode](<../../images/image (562).png>)

Da biste pokrenuli emulaciju na željenom mestu, postavite bp na to mesto; izgleda da će Cutter automatski pokrenuti emulaciju odatle:

![Postavljanje breakpoint-a na željenu ulaznu tačku shellcode-a pre pokretanja Cutter emulacije](<../../images/image (589).png>)

![Cutter emulator pauziran na izabranom breakpoint-u shellcode-a](<../../images/image (387).png>)

Na primer, stack možete da vidite unutar hex dump-a:

![Pregled emuliranog stack-a shellcode-a u Cutter hex dump-u](<../../images/image (186).png>)

### Uklanjanje obfuskacije shellcode-a i pronalaženje pozvanih funkcija

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

scDbg takođe ima grafički pokretač u kojem možete da izaberete željene opcije i izvršite shellcode

![Grafički pokretač scDbg-a za izbor opcija emulacije i praćenja shellcode-a](<../../images/image (258).png>)

Opcija **Create Dump** će sačuvati konačni shellcode ako se tokom rada dinamički promeni u memoriji (korisno za preuzimanje dekodiranog shellcode-a). **start offset** može biti koristan za pokretanje shellcode-a od određenog pomeraja. Opcija **Debug Shell** korisna je za otklanjanje grešaka u shellcode-u pomoću scDbg terminala (međutim, smatram da je bilo koja od ranije objašnjenih opcija bolja za tu svrhu, jer možete da koristite Ida ili x64dbg).

### Disasembliranje pomoću CyberChef-a

Otpremite datoteku sa shellcode-om kao ulaz i upotrebite sledeći recept da biste ga disasemblirali: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskacija MBA obfuskacije

Obfuskacija **Mixed Boolean-Arithmetic (MBA)** skriva jednostavne izraze kao što je `x + y` iza formula koje kombinuju aritmetičke (`+`, `-`, `*`) i bitovske operatore (`&`, `|`, `^`, `~`, pomeranja). Važno je da su ovi identiteti obično tačni samo uz **modularnu aritmetiku fiksne širine**, pa su prenosi i prekoračenja bitni:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ako ovaj tip izraza pojednostavite pomoću generičkih alata za algebru, lako možete dobiti pogrešan rezultat jer semantika širine bita nije uzeta u obzir.<sup>[[1]](#references)</sup>

### Praktični tok rada

1. **Sačuvajte originalnu širinu bita** iz podignutog koda/IR izlaza/dekompajlerskog izlaza (`8/16/32/64` bita).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
   - **Linearni**: ponderisani zbirovi bitovskih atoma
   - **Semilinearni**: linearni izrazi sa konstantnim maskama kao što je `x & 0xFF`
   - **Polinomski**: pojavljuju se proizvodi
   - **Mešoviti**: proizvodi i bitovska logika su isprepletani, često sa ponovljenim podizrazima
3. **Proverite svako predloženo preuređivanje** nasumičnim testiranjem ili SMT dokazom. Ako se ekvivalencija ne može dokazati, zadržite originalni izraz umesto da nagađate.

### Zaobiđite spljošteni kontrolni tok uskim izvršnim isečkom

Rekonstrukcija kompletnog grafa kontrolnog toka često nije potrebna. Kod spljoštavanja kontrolnog toka, neprozirnih predikata, velikih dispečera ili koda prepunog MBA izraza, pratite reference od šifrovanih blobova i izlaznih bafera do najmanje rutine koja ih transformiše. Zatim reprodukujte samo taj isečak toka podataka ili ga izvršite nezavisno; dispečer nije deo potrebnog rešenja ako se relevantno stanje može direktno inicijalizovati.<sup>[[7]](#references)</sup>

Praktični tok rada je:<sup>[[7]](#references)</sup>

1. Popišite izvršne i podatkovne sekcije, relokacije i unakrsne reference. Izdvojite potencijalne tabele iz `.rodata`, čuvajući redosled bajtova i širinu elemenata.
2. Identifikujte poslednju rutinu koja upisuje otvoreni tekst ili izlazni bafer. Zabeležite njene ulaze, referencirane tabele, uvezene pozive i potrebno globalno stanje.
3. Podignite samo te operacije u Python model fiksne širine. Ako isečak i dalje zavisi od previše stanja, pozovite rutinu pomoću Unicorn-а, QEMU-а ili debagera i zakačite nebitne uvezene funkcije umesto da emuliрате ceo program.
4. Potvrdite da ekstraktor zaista izvodi izlaz iz dostavljenog binarnog fajla: uklonite tihe rezervne opcije, pretražite ga u potrazi za ugrađenim odgovorima i pokrenite ga na neviđenim verzijama sa izmenjenim stringovima, ključevima, identifikatorima, rasporedima i seed vrednostima za obfuskaciju.

Korisne komande za prvi prolaz su:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Otkrivanje MBA izraza koji prikrivaju konstante

Izraz za bajt koji naizgled zavisi od ulaza može u potpunosti poništiti uticaj ulaza. Nakon izdvajanja njegovih tabela, izračunajte vrednosti izraza za ceo 8-bitni domen; skup izlaznih vrednosti koji sadrži samo jednu vrednost dokazuje da je taj bajt konstanta, bez potrebe za rekonstruisanjem okolne mašine stanja.<sup>[[7]](#references)</sup>

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

Zadržite završni mask zato što originalno sabiranje ima prelivanje pri širini bajta. Za širi domen, pitajte SMT solver da li je izraz `f(x1) != f(x2)` zadovoljiv za dva simbolička ulaza iste širine: `unsat` dokazuje invarijantnost, dok `sat` daje kontraprimer i znači da se ulaz ne može odbaciti.<sup>[[7]](#references)</sup>

#### Prepoznajte dekodiranje vezano za okruženje

Provere protiv analize ne moraju da granaju tok izvršavanja niti da izazovu pad. Dekoder može da umeša rezultat senzora u bit ključa, konstantu opaque-predicate-a ili stanje flattened-dispatcher-a, da nastavi normalno i da u emulatoru proizvede uverljiv, ali netačan plaintext. Zato nije dovoljno zakrpiti samo vidljive grane koje dovode do greške; pratite zavisnosti podataka od provera okruženja do stanja dekodera, uporedite isti segment na autentičnom uređaju i emulatoru i testirajte kako forsiranje svakog rezultata senzora menja završni bafer.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktičan MBA pojednostavljivač za analizu malware-a i reversing zaštićenih binarnih fajlova. Klasifikuje izraz i prosleđuje ga specijalizovanim procesnim cevovodima, umesto da primenjuje jedan generički prolaz za prepisivanje na sve izraze.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evaluira izraz nad Booleovim ulazima, izvodi potpis i istovremeno pokreće nekoliko metoda oporavka, kao što su uparivanje obrazaca, ANF konverzija i interpolacija koeficijenata.
- **Semilinear MBA**: atomi maskirani konstantama ponovo se grade rekonstrukcijom podeljenom po bitovima, tako da maskirani regioni ostanu ispravni.
- **Polynomial/Mixed MBA**: proizvodi se razlažu na jezgra, a ponovljeni podizrazi mogu se izdvojiti u privremene promenljive pre pojednostavljivanja spoljašnje relacije.

Primer mešovitog identiteta koji često vredi pokušati oporaviti:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Ovo se može svesti na:

```c
x * y
```

### Beleške o reverse engineeringu

- Prednost dajte pokretanju CoBRA nad **lifted IR izrazima** ili izlazom dekompilatora, nakon što izdvojite tačan proračun.
- Koristite `--bitwidth` eksplicitno ako izraz potiče od maskirane aritmetike ili registara uže širine.
- Ako vam je potreban jači korak dokazivanja, pogledajte lokalne Z3 beleške ovde:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA se isporučuje i kao **LLVM pass plugin** (`libCobraPass.so`), što je korisno kada želite da normalizujete LLVM IR sa mnogo MBA operacija pre kasnijih passes za analizu.
- Nepodržane mešovite reziduale osetljive na prenos tretirajte kao signal da zadržite originalni izraz i ručno analizirate put prenosa.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuscator zamenjuje programske operacije nizovima instrukcija zasnovanim na `mov` i koristi obradu signala/izuzetaka za izmenu toka kontrole. Detalji:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Za podržane binarne datoteke, [demovfuscator](https://github.com/kirschju/demovfuscator) može da deobfuscira rezultat. Ima nekoliko zavisnosti.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

I [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako igrate **CTF, ovo zaobilazno rešenje za pronalaženje zastavice** može biti veoma korisno: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **ulaznu tačku**, pretražite funkcije po `::main`, kao u primeru:

![Pronalaženje ulazne tačke za Rust u Ghidri pretragom naziva funkcija po dvostrukoj dvotački main](<../../images/image (1080).png>)

U ovom slučaju, binarni fajl se zvao authenticator, pa je prilično očigledno da je ovo zanimljiva main funkcija.\
Kada imate **nazive** pozvanih **funkcija**, potražite ih na **Internetu** da biste saznali više o njihovim **ulazima** i **izlazima**.

### Oporavljanje Rust stringova iz ELF firmvera

U **Rust ELF** binarnim fajlovima, mnogi statički stringovi nisu referencirani kao pokazivači u stilu C koji se završavaju NUL bajtom. Uobičajen raspored u `rustc`-u je **torka pokazivač/dužina** unutar **`.data.rel.ro`**, koja pokazuje ka stvarnom bloku stringova uskladištenom u **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

To znači da `strings` ili podrazumevana Ghidra analiza mogu da spoje susedne stringove ili potpuno propuste unakrsne reference.<sup>[[3]](#references)</sup>

Brzi tok rada:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pronađite virtuelnu adresu i veličinu sekcije **`.rodata`**.
2. Prođite kroz **`.data.rel.ro`** reč po reč.
3. Svaku vrednost unutar opsega adresa `.rodata` tretirajte kao kandidata za pokazivač na string.
4. Sledeću reč tretirajte kao kandidatsku dužinu.
5. Primenite filtere za proveru smislenosti (na primer, zadržite dužine između **4** i **100** bajtova).
6. Iz `.rodata` pročitajte tačno `length` bajtova, umesto da skenirate do `0x00`.

Minimalna logika ekstraktora:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Ovo je naročito korisno pri reverznom inženjeringu firmware-a, jer izdvojeni Rust stringovi često otkrivaju **HTTP rute, RPC nazive, poruke u logovima, provere, nazive datoteka, konfiguracione ključeve, obrađivače komandi i logiku povezanu sa autentifikacijom**.

Ako Ghidra ne pronađe te stringove, pokrenite prilagođenu skriptu/dodatak koji primenjuje istu heuristiku i kreira podatke tipa string na referenciranim `.rodata` pomerajima. Alatke `rust-strings` i `RustStrings.py` koje je objavio Pen Test Partners korisne su kao reference za prilagođavanje ove ideje drugim **širinama reči, redosledima bajtova i rasporedima sekcija**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Za binarne datoteke kompajlirane iz Delphi-ja možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako treba da radite reverzni inženjering Delphi binarne datoteke, predlažem da koristite IDA dodatak [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pritisnite **Alt+F7** u IDA-i da učitate Python dodatak, a zatim izaberite datoteku dodatka.

Ovaj dodatak će pokrenuti binarnu datoteku i dinamički razrešiti nazive funkcija na početku otklanjanja grešaka. Nakon pokretanja otklanjanja grešaka, ponovo pritisnite dugme Start (zeleno dugme ili f9) i tačka prekida će se aktivirati na početku stvarnog koda.

Ako pritisnete dugme u grafičkoj aplikaciji, program za otklanjanje grešaka može da se zaustavi u funkciji koju to dugme poziva.

## Golang

Za uobičajene Go binarne datoteke, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) može da izdvoji runtime strukture i poboljša nazive funkcija u IDA-i. Učitajte njegov Python dodatak pomoću **Alt+F7**.

### Izdvajanje metapodataka bez tabele simbola

Čak i Go izvršna datoteka bez simbola i dalje zahteva runtime metapodatke za preslikavanje programskih brojača u funkcije. [GoReSym](https://github.com/mandiant/GoReSym) pronalazi i parsira strukture kao što su `pclntab` i `moduledata` koristeći kod izveden iz Go runtime-a. Tako može da izdvoji granice funkcija, nazive, izvorne putanje, tipove i detalje o izgradnji bez oslanjanja na konvencionalnu tabelu simbola.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator može da ostavi te strukture upotrebljivim, a da pritom zameni oporavljena imena. Garble, na primer, hešira identifikatore i putanje paketa i uklanja build, module i debug informacije.<sup>[[12]](#references)</sup> Obfuscirani token paketa mora da ostane dosledan u svim funkcijama iz tog paketa. Grupisati funkcije prema tokenu koji se ponavlja, zaključiti o kom je paketu reč na osnovu njegovih pozvanih funkcija, stringova i API-ja, a zatim tu oznaku paketa preneti na celu grupu.<sup>[[13]](#references)</sup>

### Oporavak Garble imena pomoću GoResolver-a

[GoResolver](https://github.com/volexity/GoResolver) objedinjuje izdvajanje runtime simbola, generisanje čistih referenci i uparivanje grafova toka kontrole (CFG). Koristite sledeći redosled:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifikujte verziju kompajlera.** Najpre proverite `BuildInfo` i ugrađene nizove verzija. Ako ih je obfuscator uklonio, uporedite delove Go runtime-a iz binarne datoteke sa runtime-ovima za referencu po verzijama. U Volexity-jevim testovima, oko `2%` runtime-a bilo je dovoljno za razlikovanje glavnih Go verzija. Smatrajte ovo empirijskom optimizacijom, a ne univerzalnim pragom.<sup>[[13]](#references)</sup>
2. **Napravite odgovarajuće reference.** Generišite čiste binarne datoteke za identifikovanu verziju Go-a, ciljnu arhitekturu i verovatne biblioteke. Usklađivanje lanca alata smanjuje razlike u CFG-u koje uvodi kompajler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Uporedite funkcije.** GoGrapher uparuje CFG-ove funkcija i daje normalizovane ocene od `0.0` do `1.0`. Uparivanje osnovnih blokova zasniva se na ponderisanom poređenju sličnih instrukcija. Uparivanja sa visokim stepenom pouzdanosti povezuju nasumično imenovane funkcije sa čistom implementacijom. Slabija uparivanja i dalje mogu da identifikuju paket ili modul.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Proverite i uvezite.** Potvrdite predložena imena na osnovu odnosa poziva, konstanti, stringova i sporednih efekata, a zatim uvezite JSON izveštaj pomoću GoResolver dodatka za IDA ili Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instalirajte lanac alata i pokrenite objedinjeni ekstraktor i uparivač grafova:<sup>[[10]](#references)</sup>

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

Podrazumevani prag značajnog poklapanja je `0.9`. Prekidači `--extract` i `--graph` mogu da izdvoje svaku fazu zasebno, dok se podrazumevano pokreću obe, jer se oporavljeni metapodaci runtime-a i dokazi iz CFG-a međusobno dopunjuju.<sup>[[10]](#references)</sup> CFG rezultati su heuristički: inlining, zastavice za build, arhitektura i razlike u verzijama biblioteka mogu da promene oblik grafa, zato sačuvajte nerazrešene funkcije umesto da im dodeljujete imena sa niskim stepenom pouzdanosti.<sup>[[13]](#references)</sup>

## Kompajlirani Python

Na ovoj stranici možete saznati kako da dođete do Python koda iz ELF/EXE binarne datoteke kompajlirane iz Python-a:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ako nabavite **binary** igre za GBA, možete koristiti različite alate da je **emulate** i **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite debug verziju_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

U programu [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_** ** možete videti kako da pritisnete dugmad za Game Boy Advance

![no$gba konfiguracija kontrola koja prikazuje mapiranje dugmadi za Game Boy Advance](<../../images/image (581).png>)

Kada se pritisne, svaki **taster ima vrednost** pomoću koje se identifikuje:

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

Dakle, u ovakvoj vrsti programa zanimljivo je **kako program obrađuje korisnički unos**. Na adresi **0x4000130** pronaći ćete često prisutnu funkciju: **KEYINPUT**.

![Ghidra prikaz GBA binarne datoteke koja upućuje na KEYINPUT na adresi 0x4000130](<../../images/image (447).png>)

Na prethodnoj slici možete videti da se funkcija poziva iz **FUN_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekoliko operacija inicijalizacije (koje nisu važne):

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

Poslednji if proverava da li se **`uVar4`** nalazi među **prethodnim tasterima** i da nije trenutni taster — odnosno, da li je taster otpušten (trenutni taster se čuva u **`uVar1`**).

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

- Prvo se poredi sa **vrednošću 4** (dugme **SELECT**): u izazovu ovo dugme briše ekran
- Zatim se vrednost poredi sa **8** (dugme **START**); u ovom izazovu ta grana proverava da li je uneti kod ispravan.
  - U tom slučaju, varijabla **`DAT_030000d8`** poredi se sa 0xf3 i ako su vrednosti jednake, izvršava se određeni kod.
- U svim ostalim slučajevima proverava se i uvećava brojač (`DAT_030000d4`).\
  Dok je brojač manji od 8, vrednosti pritisnutih tastera sabiraju se u `DAT_030000d8`.

Dakle, u ovom izazovu, pošto znate vrednosti dugmadi, trebalo je da **pritisnete kombinaciju kraću od 8 dugmadi čiji je zbir 0xf3.**

**Referenca za ovaj vodič:** [arhivirani opis rešenja izazova Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursevi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (deobfuskacija binarnih datoteka)

## References

- [1] [Pojednostavljivanje MBA obfuskacije pomoću CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repozitorijum](https://github.com/trailofbits/CoBRA)
- [3] [Dekodiranje Rust stringova - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - vodič za reversing na GBA-u (arhivirano)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Pobeda nad AI-potpomognutim reverse engineeringom, ili bar pokušaj](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Pristup poređenju grafova toka kontrole zasnovan na uparivanju osnovnih blokova](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mehanizam obfuskacije Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Korišćenje sličnosti grafova toka kontrole za automatsku deobfuskaciju Go binarnih datoteka](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
