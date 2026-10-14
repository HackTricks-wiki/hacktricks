# Alati za reverse engineering i osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## Alati za reverse engineering zasnovani na ImGui

Softver:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Debugovanje Windows kernela

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Onlajn:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) za **dekompajliranje** wasm (binarnog) koda u wat (čitljiv tekst)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) za **kompajliranje** wat koda u wasm
- Za dekompajliranje možete isprobati i [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Softver:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 keširani bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtuelizovani payloadi i prilagođene VM-ove

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je decompiler koji **dekompajlira i pregleda više formata**, uključujući **biblioteke** (.dll), **Windows metadata datoteke** (.winmd) i **izvršne datoteke** (.exe). Nakon dekompajliranja, assembly se može sačuvati kao Visual Studio projekat (.csproj).

Ovo je korisno jer, ako je potrebno obnoviti izgubljeni izvorni kod iz zastarelog assembly-ja, to može uštedeti vreme. Pored toga, dotPeek omogućava jednostavnu navigaciju kroz dekompajlirani kod, što ga čini jednim od savršenih alata za **analizu Xamarin algoritama.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Zahvaljujući sveobuhvatnom modelu dodataka i API-ju koji omogućava prilagođavanje alata vašim potrebama, .NET Reflector štedi vreme i pojednostavljuje razvoj. Pogledajmo mnoštvo usluga za reverse engineering koje ovaj alat pruža:

- Omogućava uvid u tok podataka kroz biblioteku ili komponentu
- Omogućava uvid u implementaciju i upotrebu .NET jezika i framework-a
- Pronalaženje nedokumentirane i neizložene funkcionalnosti radi boljeg iskorišćavanja korišćenih API-ja i tehnologija.
- Pronalaženje zavisnosti i različitih assembly-ja
- Pronalaženje tačne lokacije grešaka u vašem kodu, komponentama trećih strana i bibliotekama.
- Debugovanje izvornog koda celokupnog .NET koda s kojim radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy dodatak za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga instalirati direktno iz VSCode-a, bez preuzimanja git-a. Kliknite na **Extensions** i **potražite ILSpy**).\
Ako treba da **dekompajlirate**, **izmenite** i ponovo **kompajlirate**, možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegov aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknite desnim tasterom miša -> Modify Method** da biste nešto promenili unutar funkcije).

### Inspekcija upravljanog koda bez izvršavanja pomoću REA

**REA** može da pregleda PE/CLI metadata i CIL bez učitavanja assembly-ja. Započnite identifikacijom artefakta, a zatim pregledajte članove i deklarisane granice izvornog koda; ovo je korisno pri proveri sumnjivih poziva pre upotrebe decompiler-a ili pokretanja programa.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Za poređenje verzija, `compare_managed_members` koristi sirovi CIL/signature identity i decoded-instruction fingerprints, umesto da tretira metadata tokens kao stabilne između buildova. P/Invoke deklaracija nije dokaz da je native code pokrenut; `verify_managed_native_boundaries` zahteva odgovarajući native export ili function Evidence da bi proverio tu granicu. Sačuvajte artifact digest, MVID i unresolved mappings uz rezultat.<sup>[[17]](#references)</sup>

### DNSpy beleženje

Da biste **DNSpy naveli da zabeleži neke informacije u datoteku**, možete koristiti ovaj isečak:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Otklanjanje grešaka u DNSpy-u

Da biste otklanjali greške u kodu pomoću DNSpy-a, potrebno je da:

Prvo promenite **atribute sklopa** koji se odnose na **otklanjanje grešaka**:

![DNSpy Logging - Otklanjanje grešaka u DNSpy-u: Prvo promenite atribute sklopa koji se odnose na otklanjanje grešaka](<../../images/image (973).png>)

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

Ovo je neophodno jer će se, ako to ne uradite, pri **runtime**-u na kod primeniti nekoliko **optimizacija**, pa je moguće da tokom debugginga **break-point nikada ne bude dostignut** ili da neke **promenljive ne postoje**.

Zatim, ako vašu .NET aplikaciju **pokreće** **IIS**, možete je **restartovati** pomoću:

```
iisreset /noforce
```

Zatim, da biste započeli debugovanje, zatvorite sve otvorene datoteke, pa na kartici **Debug** izaberite **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste započeli debugovanje, zatvorite sve otvorene datoteke, pa na kartici Debug izaberite Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste se povezali sa **IIS serverom** i kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste se povezali sa IIS serverom i kliknite na attach](<../../images/image (113).png>)

Sada kada debugujemo proces, zaustavite ga i učitajte sve module. Najpre kliknite na _Debug >> Break All_, a zatim na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, zaustavite ga i učitajte sve module. Najpre kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, zaustavite ga i učitajte sve module. Najpre kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u prozoru **Modules**, pa izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u prozoru Modules, pa izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom miša na bilo koji modul u **Assembly Explorer** i kliknite na **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom miša na bilo koji modul u Assembly Explorer i kliknite na Sort Assemblies](<../../images/image (339).png>)

## Java dekompajler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugovanje DLL-ova

### Korišćenje IDA

- **Učitajte rundll32** (64-bitna verzija se nalazi u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- Izaberite debugger **Windbg**
- Izaberite "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Podesite **parametre** izvršavanja tako što ćete navesti **putanju do DLL-a** i funkciju koju želite da pozovete:

![Debugging DLLs - Using IDA: Podesite parametre izvršavanja tako što ćete navesti putanju do DLL-a i funkciju koju želite da pozovete](<../../images/image (704).png>)

Zatim, kada započnete debugovanje, **izvršavanje će se zaustaviti pri učitavanju svake DLL datoteke**. Dakle, kada rundll32 učita vaš DLL, izvršavanje će se zaustaviti.

Ovaj metod zaustavlja izvršavanje pri događajima učitavanja modula, ali dolazak do ulazne tačke učitanog DLL-a manje je direktan nego u x64dbg postupku u nastavku.

### Korišćenje x64dbg/x32dbg

- **Učitajte rundll32** (64-bitna verzija se nalazi u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- **Promenite Command Line** (_File --> Change Command Line_) i navedite putanju do DLL-a i funkciju koju želite da pozovete, na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Otvorite _Options --> Settings_ i izaberite "**DLL Entry**".
- Zatim **pokrenite izvršavanje**. Debugger će se zaustaviti na svakom dll main-u; u nekom trenutku će se **zaustaviti na ulaznoj tački vašeg DLL-a**. Odatle samo pronađite mesta na koja želite da postavite breakpoint.

Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, **na kom kodu se nalazite** možete da vidite **na vrhu prozora win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, na kom kodu se nalazite možete da vidite na vrhu prozora win64dbg](<../../images/image (842).png>)

Ovaj indikator potvrđuje da je izvršavanje zaustavljeno unutar DLL-a koji želite da debugujete.

## GUI aplikacije / video-igre

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje važnih vrednosti sačuvanih u memoriji pokrenute igre i njihovu izmenu. Više informacija:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end / alat za reverse engineering za GNU Project Debugger (GDB), namenjen prvenstveno igrama. Međutim, može da se koristi za bilo šta u vezi sa reverse engineering-om.

[**Decompiler Explorer**](https://dogbolt.org/) je veb front-end za više dekompajlera. Ova veb-usluga omogućava poređenje rezultata različitih dekompajlera za manje izvršne datoteke.

## Istraga nativnog koda zasnovana na dokazima uz REA

**REA** omogućava pristup analizama iz Hopper-a, Ghidra-e i IDA-e preko CLI-ja i MCP-a. Potrebni su Node.js 22.x (najmanje 22.19), 24.x (najmanje 24.11) ili 26+, kao i npm. Najpre konfigurišite postojeći nativni provider; proverite `rea providers --json` i izričito izaberite provider ako ih više podržava cilj. Umesto `0x1000` u nastavku koristite ime funkcije ili adresu iz inventara koje ste uočili.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Počnite od stringa funkcije ili simbola, pratite reference i pozivaoce, a zatim pregledajte dosije izabrane funkcije i pseudokod pomoću `rea decompile`. REA vezuje sesiju za izabranog provajdera umesto da ga neprimetno zameni nakon greške. Za ponovljive upite, `--snapshot PATH` ponovo koristi samo bajtove artefakta, provajdera, podešavanja, operaciju i parametre koji se poklapaju; snapshot je lokalni keš, a ne sačuvana baza podataka provajdera. Sačuvajte vraćeni Evidence i eksplicitno navedene nepoznanice umesto da izvedene putanje ili tekst dekompajlera tretirate kao izvorni kod.<sup>[[16]](#references)[[18]](#references)</sup>

Za JavaScript/Electron ulazne tačke koje vode do native dodataka, pogledajte [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugovanje shellcode-a pomoću blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alocira **shellcode**, ispisuje njegovu **memorijsku adresu** i pauzira izvršavanje.\
Prikačite debugger kao što je IDA ili x64dbg, postavite breakpoint na ispisanu adresu i nastavite izvršavanje da biste debugovali shellcode.

Na GitHub stranici izdanja nalaze se zip arhive sa kompajliranim izdanjima: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blago izmenjenu verziju Blobrunner-a možete pronaći na sledećem linku. Da biste je kompajlirali, samo **napravite C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod, pa ga izgradite**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugovanje shellcode-a pomoću jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je sličan alatu BlobRunner. Alocira shellcode i ulazi u beskonačnu petlju. Prikačite debugger, nastavite izvršavanje na **2–5 sekundi**, pauzirajte unutar te petlje i pređite na sledeći poziv koji prenosi izvršavanje na alocirani shellcode.

![Debugger pauziran u beskonačnoj petlji alata jmp2it neposredno pre poziva alociranog shellcode-a](<../../images/image (509).png>)

Kompajliranu verziju alata [jmp2it možete preuzeti na stranici izdanja](https://github.com/adamkramer/jmp2it/releases/).

### Debugovanje shellcode-a pomoću Cutter-a

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI za radare. Pomoću Cutter-a možete emulirati shellcode i dinamički ga pregledati.

Imajte na umu da Cutter omogućava „Open File“ i „Open Shellcode“. U mom slučaju, kada sam otvorio shellcode kao datoteku, ispravno ga je dekompajlirao, ali kada sam ga otvorio kao shellcode, nije:

![Cutter prikazuje različite rezultate analize kada se isti bajtovi otvore kao datoteka ili kao shellcode](<../../images/image (562).png>)

Da bi emulacija počela na željenom mestu, tamo postavite bp; čini se da će Cutter automatski pokrenuti emulaciju odatle:

![Postavljanje breakpoint-a na željeno ulazno mesto shellcode-a pre pokretanja emulacije u Cutter-u](<../../images/image (589).png>)

![Emulator u Cutter-u pauziran na izabranom breakpoint-u shellcode-a](<../../images/image (387).png>)

Na primer, stek možete videti u hex dump-u:

![Prikaz emuliranog steka shellcode-a u hex dump-u alata Cutter](<../../images/image (186).png>)

### Deobfuskacija shellcode-a i pronalaženje izvršenih funkcija

Probajte [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Pokazaće vam stvari kao što su **koje funkcije** shellcode koristi i da li se **dekodira** u memoriji.

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

Opcija **Create Dump** izbacuje konačni shellcode ako se on dinamički promeni u memoriji (korisno za preuzimanje dekodiranog shellcode-a). Opcija **start offset** može biti korisna za pokretanje shellcode-a od određenog pomeraja. Opcija **Debug Shell** korisna je za otklanjanje grešaka u shellcode-u pomoću scDbg terminala (međutim, smatram da je bilo koja od prethodno objašnjenih opcija bolja za ovu namenu, jer ćete moći da koristite Ida ili x64dbg).

### Disasembliranje pomoću CyberChef-a

Otpremite datoteku shellcode-a kao ulaz i upotrebite sledeći recept da biste je dekompilirali: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Uklanjanje MBA obfuskacije

Obfuskacija **Mixed Boolean-Arithmetic (MBA)** skriva jednostavne izraze kao što je `x + y` iza formula koje kombinuju aritmetičke operatore (`+`, `-`, `*`) i bitovne operatore (`&`, `|`, `^`, `~`, pomeranja). Važno je da su ovi identiteti obično tačni samo u okviru **modularne aritmetike fiksne širine**, pa su prenosi i prekoračenja bitni:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ako pojednostavite ovu vrstu izraza pomoću generičkih alata za algebru, lako možete dobiti pogrešan rezultat jer je zanemarena semantika širine bitova.<sup>[[1]](#references)</sup>

### Praktični postupak

1. **Zadržite originalnu širinu bitova** iz podignutog koda/IR-a/izlaza dekompilatora (`8/16/32/64` bita).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
   - **Linearni**: ponderisani zbirovi bitovskih atoma
   - **Semilinearni**: linearni izrazi uz konstantne maske, kao što je `x & 0xFF`
   - **Polinomski**: sadrže proizvode
   - **Mešoviti**: proizvodi i bitovska logika su isprepletani, često sa ponovljenim podizrazima
3. **Proverite svaku predloženu transformaciju** nasumičnim testiranjem ili SMT dokazom. Ako se ekvivalencija ne može dokazati, zadržite originalni izraz umesto da nagađate.

### Zaobiđite spljošteni kontrolni tok pomoću uskog izvršnog isečka

Rekonstrukcija kompletnog grafa kontrolnog toka često nije potrebna. Kod spljoštavanja kontrolnog toka, neprozirnih predikata, velikih dispečera ili koda sa mnogo MBA izraza, pratite reference od šifrovanih blokova i izlaznih bafera do najmanje rutine koja ih transformiše. Zatim reprodukujte samo taj isečak toka podataka ili ga izvršite nezavisno; dispečer nije deo potrebnog rešenja ako se relevantno stanje može direktno inicijalizovati.<sup>[[7]](#references)</sup>

Praktični postupak je:<sup>[[7]](#references)</sup>

1. Napravite popis izvršnih sekcija i sekcija sa podacima, relokacija i unakrsnih referenci. Izdvojite potencijalne tabele iz `.rodata`, čuvajući njihov redosled bajtova i širinu elemenata.
2. Identifikujte poslednju rutinu koja upisuje plaintext ili izlazni bafer. Zabeležite njene ulaze, referencirane tabele, uvezene pozive i potrebno globalno stanje.
3. Prenesite samo te operacije u Python model fiksne širine. Ako isečak i dalje zavisi od previše stanja, pozovite rutinu pomoću Unicorn-a, QEMU-a ili debagera i presretnite nebitne uvezene funkcije umesto da emulirate ceo program.
4. Potvrdite da ekstraktor zaista izvodi svoj izlaz iz dostavljenog binarnog fajla: uklonite tihe rezervne putanje, pretražite ga u potrazi za ugrađenim odgovorima i pokrenite ga na ranije neviđenim verzijama sa izmenjenim stringovima, ključevima, identifikatorima, rasporedima i seedovima za obfuskaciju.

Korisne početne komande su:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Detektovanje MBA izraza koji su maskirane konstante

Izraz nad bajtom koji naizgled zavisi od ulaza može u potpunosti poništiti svoj ulaz. Nakon izdvajanja njegovih tabela, evaluirajte izraz nad celim 8-bitnim domenom; skup izlaznih vrednosti koji sadrži samo jednu vrednost dokazuje da je taj bajt konstanta, bez potrebe za rekonstrukcijom okolne mašine stanja.<sup>[[7]](#references)</sup>

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

Zadržite završnu masku jer se pri originalnom sabiranju vrednost prelama na širinu bajta. Za širi domen, pitajte SMT solver da li je izraz `f(x1) != f(x2)` zadovoljiv za dva simbolička ulaza iste širine: `unsat` dokazuje nepromenljivost, dok `sat` daje kontraprimer i znači da se ulaz ne može odbaciti.<sup>[[7]](#references)</sup>

#### Prepoznajte dekodiranje vezano za okruženje

Provere protiv analize ne moraju da izazovu grananje ili pad. Dekoder može da umeša rezultat senzora u bit ključa, konstantu opaque-predicate-a ili stanje flattenovanog dispečera, da nastavi normalno i proizvede uverljiv, ali netačan čist tekst u emulatoru. Zato nije dovoljno zakrpiti samo vidljive grane greške; pratite zavisnosti podataka od sondi okruženja do stanja dekodera, uporedite isti isečak na autentičnom uređaju i emulatoru i proverite kako forsiranje svakog rezultata senzora menja konačni bafer.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktičan MBA pojednostavljivač za analizu malvera i reverzni inženjering zaštićenih binarnih datoteka. Klasifikuje izraz i usmerava ga kroz specijalizovane tokove obrade, umesto da na sve primenjuje jedan generički prolaz za prepisivanje.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evaluira izraz nad Boolean ulazima, izvodi potpis i istovremeno pokreće nekoliko metoda za oporavak, kao što su uparivanje obrazaca, ANF konverzija i interpolacija koeficijenata.
- **Semilinear MBA**: atomi maskirani konstantama rekonstruišu se pomoću rekonstrukcije podeljene po bitovima, tako da maskirani regioni ostanu ispravni.
- **Polynomial/Mixed MBA**: proizvodi se razlažu na jezgra, a ponovljeni podizrazi mogu se izdvojiti u privremene promenljive pre pojednostavljivanja spoljne relacije.

Primer mešovitog identiteta koji često vredi pokušati rekonstruisati:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Ovo se može svesti na:

```c
x * y
```

### Napomene o reverznom inženjerstvu

- Prednost dajte pokretanju CoBRA nad **podignutim IR izrazima** ili izlazom dekompilatora, nakon što izdvojite tačan proračun.
- Koristite `--bitwidth` izričito ako je izraz nastao iz maskirane aritmetike ili registara uske širine.
- Ako vam je potreban jači korak dokazivanja, pogledajte lokalne Z3 beleške ovde:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA se isporučuje i kao **LLVM pass plugin** (`libCobraPass.so`), što je korisno kada želite da normalizujete LLVM IR sa mnogo MBA izraza pre kasnijih prolaza za analizu.
- Nepodržane mešovite reziduale osetljive na prenos tretirajte kao signal da zadržite originalni izraz i ručno analizirate putanju prenosa.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuskator zamenjuje operacije programa nizovima instrukcija zasnovanih na `mov` i koristi rukovanje signalima/izuzecima za izmenu toka kontrole. Detalji:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Za podržane binarne fajlove, [demovfuscator](https://github.com/kirschju/demovfuscator) može da deobfuskuje rezultat. Ima nekoliko zavisnosti.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

I [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako igrate **CTF, ovo zaobilazno rešenje za pronalaženje flag-a** može biti veoma korisno: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **ulaznu tačku**, pretražite funkcije po `::main`, kao u primeru:

![Pronalaženje ulazne tačke Rust programa u Ghidri pretragom naziva funkcija za dvotačku-dvotačku main](<../../images/image (1080).png>)

U ovom slučaju, binarna datoteka se zvala authenticator, pa je prilično očigledno da je ovo zanimljiva main funkcija.\
Kada saznate **nazive** pozivanih **funkcija**, potražite ih na **Internetu** da biste saznali koji su njihovi **ulazi** i **izlazi**.

### Oporavak Rust stringova iz ELF firmvera

U **Rust ELF** binarnim datotekama, mnogi statički stringovi nisu referencirani kao pokazivači terminisani NUL-om u C stilu. Uobičajeni `rustc` raspored je **torka pokazivač/dužina** unutar **`.data.rel.ro`**, koja pokazuje na stvarni blok stringova smešten u **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

To znači da `strings` ili podrazumevana Ghidra analiza mogu spojiti susedne stringove ili potpuno propustiti unakrsne reference.<sup>[[3]](#references)</sup>

Brzi tok rada:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pronađite virtuelnu adresu i veličinu sekcije **`.rodata`**.
2. Enumerišite **`.data.rel.ro`** reč po reč.
3. Svaku vrednost unutar adresnog opsega `.rodata` tretirajte kao mogući pokazivač na string.
4. Sledeću reč tretirajte kao moguću dužinu.
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

Ovo je naročito korisno pri reverse engineering-u firmware-a, jer oporavljeni Rust stringovi često otkrivaju **HTTP rute, RPC nazive, log poruke, assert-ove, nazive datoteka, konfiguracione ključeve, obrađivače komandi i logiku povezanu sa autentifikacijom**.

Ako Ghidra ne pronađe te stringove, pokrenite prilagođenu skriptu/dodatak koja primenjuje istu heuristiku i kreira string podatke na referenciranim `.rodata` pomerajima. Objavljeni alati `rust-strings` i `RustStrings.py` kompanije Pen Test Partners dobri su izvori za prilagođavanje ove ideje drugim **veličinama reči, redosledima bajtova i rasporedima sekcija**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Za binarne fajlove kompajlirane za Delphi možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako treba da analizirate Delphi binarni fajl, predlažem da koristite IDA dodatak [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pritisnite **Alt+F7** u IDA-i da biste učitali Python dodatak, a zatim izaberite datoteku dodatka.

Ovaj dodatak će izvršiti binarni fajl i dinamički razrešiti nazive funkcija na početku otklanjanja grešaka. Nakon pokretanja otklanjanja grešaka, ponovo pritisnite dugme Start (zeleno dugme ili f9) i breakpoint će se aktivirati na početku stvarnog koda.

Ako pritisnete dugme u grafičkoj aplikaciji, debugger može da se zaustavi u funkciji koju to dugme poziva.

## Golang

Za uobičajene Go binarne fajlove, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) može da oporavi runtime strukture i poboljša nazive funkcija u IDA-i. Učitajte njegov Python dodatak pomoću **Alt+F7**.

Ako treba da analizirate Go binarni fajl, predlažem da koristite IDA dodatak [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pritisnite **Alt+F7** u IDA-i da biste učitali Python dodatak, a zatim izaberite datoteku dodatka.

Ovo će razrešiti nazive funkcija.

### Oporavak metapodataka bez tabele simbola

Čak i Go izvršna datoteka iz koje su uklonjeni simboli i dalje zahteva runtime metapodatke za mapiranje programskih brojača na funkcije. [GoReSym](https://github.com/mandiant/GoReSym) pronalazi i obrađuje strukture kao što su `pclntab` i `moduledata`, koristeći kod izveden iz Go runtime-a. Tako može da oporavi granice funkcija, nazive, putanje izvornog koda, tipove i informacije o izgradnji bez oslanjanja na konvencionalnu tabelu simbola.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuskator može da ostavi te strukture upotrebljivim, a da zameni pronađena imena. Garble, na primer, hešira identifikatore i putanje paketa i uklanja informacije o build-u, modulima i otklanjanju grešaka.<sup>[[12]](#references)</sup> Obfuskovani token paketa mora da bude isti u svim funkcijama iz tog paketa. Grupisati funkcije prema tokenu koji se ponavlja, zaključiti koji je paket na osnovu njegovih pozivanih funkcija, stringova i API-ja, a zatim tu oznaku paketa primeniti na celu grupu.<sup>[[13]](#references)</sup>

### Rekonstrukcija Garble naziva pomoću GoResolver-a

[GoResolver](https://github.com/volexity/GoResolver) objedinjuje izdvajanje runtime simbola, generisanje čistih referenci i upoređivanje grafova toka kontrole (CFG). Koristite sledeći redosled:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Utvrditi verziju kompajlera.** Najpre proveriti `BuildInfo` i ugrađene nizove verzija. Ako ih je obfuskator uklonio, uporediti delove priloženog Go runtime-a sa referentnim runtime-ovima za poznate verzije. U testovima kompanije Volexity, oko `2%` runtime-a bilo je dovoljno da se razlikuju glavne verzije Go-a. Ovo tretirajte kao empirijsku optimizaciju, a ne kao univerzalni prag.<sup>[[13]](#references)</sup>
2. **Pripremiti odgovarajuće reference.** Generisati čiste binarne datoteke za utvrđenu verziju Go-a, ciljnu arhitekturu i verovatne biblioteke. Usklađivanje toolchain-a smanjuje razlike u CFG-ovima koje stvara kompajler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Uporediti funkcije.** GoGrapher upoređuje CFG-ove funkcija i daje normalizovane ocene od `0.0` do `1.0`. Njegovo uparivanje osnovnih blokova zasniva se na ponderisanom poređenju sličnih instrukcija. Poklapanja sa visokim stepenom pouzdanosti povezuju nasumično preimenovane funkcije sa čistom implementacijom. Slabija poklapanja i dalje mogu da otkriju paket ili modul.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Proveriti i uvesti.** Potvrditi predložena imena na osnovu veza između poziva, konstanti, stringova i sporednih efekata, a zatim uvesti JSON izveštaj pomoću GoResolver dodatka za IDA ili Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instalirati toolchain i pokrenuti objedinjeni ekstraktor i alat za upoređivanje grafova:<sup>[[10]](#references)</sup>

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

Podrazumevani prag značajnog poklapanja je `0.9`. Opcije `--extract` i `--graph` mogu zasebno da pokrenu bilo koju fazu, dok se podrazumevano pokreću obe jer se oporavljeni runtime metapodaci i dokazi iz CFG-a međusobno dopunjuju.<sup>[[10]](#references)</sup> CFG ocene su heurističke: inlining, build flags, arhitektura i razlike u verzijama biblioteka mogu da promene oblik grafa, zato sačuvajte nerazrešene funkcije umesto da im dodeljujete nazive uz nizak nivo pouzdanosti.<sup>[[13]](#references)</sup>

### Oporavak Go string tabele

Go binarni fajlovi smeštaju string bajtove iz svih povezanih paketa u jednu neprekidnu tabelu. Unosi nisu završeni NUL bajtom, a runtime strukture ne otkrivaju početnu adresu ni veličinu tabele. Međutim, kompajler raspoređuje unose prvo po dužini, a zatim abecedno, bez obzira na operativni sistem i arhitekturu. Kada pronađe jedan unos, analitičar zato može da pregleda susedne unose i koristi unakrsne reference podataka da poveže stringove sa kodom.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatizuje ovaj postupak u IDA Pro i Ghidra. Najpre sačekajte da se završi automatska analiza jer dodatak koristi unakrsne reference iz segmenta podataka. Podrazumevana početna tačka je runtime string `entersyscall`; zatim dodatak može da pretražuje u oba smera, definiše oporavljene stringove u bazi podataka i izveze JSON mapiranje stringova na funkcije koje ih referenciraju.<sup>[[14]](#references)</sup>

Filtrirajte izveštaj prema paketu funkcije koja referencira string da biste odvojili kod aplikacije ili malvera od šuma povezanih biblioteka. Ova tehnika ne može da oporavi literale uništene obfuskacijom, kao što je Garbleova transformacija `-literals`. I dalje može da organizuje runtime stringove koji su ostali neobfuskirani.<sup>[[14]](#references)[[15]](#references)</sup>

### Oporavak Go runtime tipova

Go ugrađuje informacije o runtime tipovima koje koriste funkcije kao što je garbage collection. Kada su informacije o izgradnji uklonjene ili disasembler ne raščlanjuje ove metapodatke, može izgledati kao da instrukcije učitavaju proizvoljne adrese podataka, a ciljna oblast ostaje bez tipizacije. Oporavak metapodataka pretvara te adrese u čitljive reference na tipove i olakšava razumevanje mogućnosti paketa.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) može da izdvoji simbole i raščlani runtime tipove u JSON izveštaj. Trenutni CLI koristi podkomandu `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Opcija `-y`/`--types` omogućava parsiranje tipova. Uvezite izveštaj pomoću GoResolver dodatka za IDA Pro ili Ghidra da biste definisali oporavljene tipove i primenili njihove reference u bazi podataka analize. U formatu izveštaja uvedenom ovom funkcijom, ako izostavite `-y`, članovi RTTI adrese i oporavljenih tipova ostaju null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver podržava PE, ELF i Mach-O uzorke za x86, AMD64, ARM i ARM64, tako da se isti postupak primenjuje na Go binarne fajlove za Windows, Linux i macOS.<sup>[[10]](#references)</sup>

## Kompajlirani Python

Na ovoj stranici možete saznati kako da izdvojite Python kod iz kompajliranog Python binarnog fajla u ELF/EXE formatu:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ako dobijete **binarni fajl** GBA igre, možete koristiti različite alate za njenu **emulaciju** i **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite verziju za debug_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra dodatak
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra dodatak

U programu [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_** ** možete videti kako da pritisnete **dugmad** Game Boy Advance konzole

![konfiguracija kontrola u no$gba prikazuje mapiranje dugmadi za Game Boy Advance](<../../images/image (581).png>)

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

Dakle, u ovakvom programu zanimljivo je **kako program obrađuje korisnički unos**. Na adresi **0x4000130** pronaći ćete često prisutnu funkciju: **KEYINPUT**.

![Ghidra prikaz GBA binarne datoteke koja upućuje na KEYINPUT na adresi 0x4000130](<../../images/image (447).png>)

Na prethodnoj slici možete videti da se funkcija poziva iz **FUN_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekoliko inicijalizacionih operacija (bez ikakvog značaja):

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

Poslednji if proverava da li se **`uVar4`** nalazi među prethodnim tasterima i da li nije trenutni taster — odnosno da li je dugme otpušteno (trenutni taster se čuva u **`uVar1`**).

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

U prethodnom kodu možete videti da se **uVar1** (mesto na kom se nalazi **vrednost pritisnutog dugmeta**) poredi sa određenim vrednostima:

- Prvo se poredi sa **vrednošću 4** (dugme **SELECT**): u ovom izazovu ovo dugme briše ekran
- Zatim se vrednost poredi sa **8** (dugme **START**); u ovom izazovu ta grana proverava da li je uneti kod važeći.
  - U ovom slučaju, promenljiva **`DAT_030000d8`** poredi se sa 0xf3, a ako su vrednosti iste, izvršava se određeni kod.
- U svim ostalim slučajevima, proverava se i uvećava brojač (`DAT_030000d4`).\
  Dok je brojač manji od 8, vrednosti pritisnutih dugmadi sabiraju se u `DAT_030000d8`.

Dakle, u ovom izazovu, znajući vrednosti dugmadi, trebalo je **pritisnuti kombinaciju kraću od 8 dugmadi čiji je zbir 0xf3.**

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
- [6] [Nostalgia - GBA vodič za reversing (arhivirano)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Kako nadmudriti AI-potpomognuti reversing, ili bar pokušati](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Pristup poređenju grafova toka kontrole zasnovan na uparivanju osnovnih blokova](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repozitorijum](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mehanizam obfuskacije Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: korišćenje sličnosti grafova toka kontrole za automatsku deobfuskaciju Go binarnih datoteka](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repozitorijum](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: novosti u Volexity Golang alatima](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: obrnuti inženjering bilo čega](https://github.com/morluto/rea)
- [17] [REA analiza upravljanog koda](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA vodič za CLI i dokaze](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
