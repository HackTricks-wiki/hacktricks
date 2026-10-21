# Alati za reverse engineering i osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## Alati za reverse engineering zasnovani na ImGui

Softver:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automatizacija korisničkog režima u WinDbg-u

{{#ref}}
windbg-automation.md
{{#endref}}

## Kontrolni tok u Windows-u zasnovan na izuzecima

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Otklanjanje grešaka u Windows kernelu

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm dekompajler / Wat kompajler

Na mreži:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) za **dekompiliranje** iz wasm (binarnog formata) u wat (čitljiv tekst)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) za **kompiliranje** iz wat u wasm
- Za dekompiliranje možete isprobati i [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Softver:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Keširani bytecode za Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtuelizovani payload-i i prilagođene virtuelne mašine

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET dekompajler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je dekompajler koji **dekompajlira i ispituje više formata**, uključujući **biblioteke** (.dll), **datoteke Windows metapodataka** (.winmd) i **izvršne datoteke** (.exe). Nakon dekompiliranja, sklop se može sačuvati kao Visual Studio projekat (.csproj).

Prednost je u tome što, ako izgubljeni izvorni kod treba obnoviti iz starijeg sklopa, ovaj postupak može uštedeti vreme. Pored toga, dotPeek omogućava praktično kretanje kroz dekompilirani kod, što ga čini jednim od idealnih alata za **analizu Xamarin algoritama.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Zahvaljujući sveobuhvatnom modelu dodataka i API-ju koji proširuje alat kako bi odgovarao vašim potrebama, .NET Reflector štedi vreme i pojednostavljuje razvoj. Pogledajmo brojne usluge reverse engineering-a koje ovaj alat pruža:

- Pruža uvid u tok podataka kroz biblioteku ili komponentu
- Pruža uvid u implementaciju i upotrebu .NET jezika i okvira
- Pronalazi nedokumentirane i nedostupne funkcionalnosti kako biste bolje iskoristili API-je i tehnologije.
- Pronalazi zavisnosti i različite sklopove
- Otkriva tačnu lokaciju grešaka u vašem kodu, komponentama trećih strana i bibliotekama.
- Omogućava otklanjanje grešaka u izvornom kodu celokupnog .NET koda sa kojim radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy dodatak za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga instalirati direktno iz VSCode-a; git ne morate da preuzimate. Kliknite na **Extensions** i **potražite ILSpy**).\
Ako želite da **dekompajlirate**, **izmenite** i ponovo **kompajlirate**, možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegov aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknite desnim tasterom -> Modify Method** da biste nešto izmenili unutar funkcije).

### Provera upravljanih sklopova pomoću REA, bez izvršavanja

**REA** može da ispituje PE/CLI metapodatke i CIL bez učitavanja sklopa. Počnite od identiteta artefakta, a zatim pregledajte članove i deklarisane granice native koda; ovo je korisno pri proveri sumnjivih poziva pre korišćenja dekompajlera ili pokretanja programa.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Za poređenje verzija, `compare_managed_members` koristi sirovi identitet CIL-a/potpisa i otiske dekodiranih instrukcija, umesto da metapodatke tretira kao stabilne između buildova. P/Invoke deklaracija nije dokaz da je pokrenut nativni kod; `verify_managed_native_boundaries` zahteva podudaranje sa nativnim izvozom ili funkcijom Evidence da bi proverio tu granicu. Sačuvajte digest artefakta, MVID i nerazrešena mapiranja uz rezultat.<sup>[[17]](#references)</sup>

### DNSpy logovanje

Da bi DNSpy zabeležio neke informacije u datoteku, možete da koristite ovaj isečak:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy debagovanje

Da biste debagovali kod pomoću DNSpy, potrebno je da:

Prvo promenite **Assembly attributes** povezane sa **debugging**:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: Kliknite na compile](<../../images/image (314) (1).png>)

Zatim sačuvajte novu datoteku pomoću _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Zatim sačuvajte novu datoteku pomoću File Save module](<../../images/image (602).png>)

Ovo je neophodno zato što će, ako to ne uradite, tokom **runtime**-a na kod biti primenjeno nekoliko **optimisations** i moguće je da se tokom debagovanja **break-point nikada ne aktivira** ili da neke **promenljive ne postoje**.

Zatim, ako vašu .NET aplikaciju **pokreće** **IIS**, možete da je **restartujete** pomoću:

```
iisreset /noforce
```

Zatim, da biste započeli debugovanje, zatvorite sve otvorene fajlove, a zatim na kartici **Debug** izaberite **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste započeli debugovanje, zatvorite sve otvorene fajlove, a zatim na kartici Debug izaberite Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste se povezali sa **IIS serverom** i kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste se povezali sa IIS serverom i kliknite na attach](<../../images/image (113).png>)

Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na _Debug >> Break All_, a zatim na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u prozoru **Modules** i izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u prozoru Modules i izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom miša na bilo koji modul u prozoru **Assembly Explorer**, a zatim kliknite na **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom miša na bilo koji modul u prozoru Assembly Explorer, a zatim kliknite na Sort Assemblies](<../../images/image (339).png>)

## Java dekompajler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugovanje DLL-ova

### Korišćenje IDA-e

- **Učitajte rundll32** (64-bitna verzija se nalazi u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- Izaberite debugger **Windbg**
- Izaberite "**Suspend on library load/unload**"

![Debugovanje DLL-ova - Korišćenje IDA-e: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Podesite **parametre** izvršavanja tako što ćete uneti **putanju do DLL-а** i funkciju koju želite da pozovete:

![Debugovanje DLL-ova - Korišćenje IDA-e: Podesite parametre izvršavanja tako što ćete uneti putanju do DLL-а i funkciju koju želite da pozovete](<../../images/image (704).png>)

Kada započnete debugovanje, **izvršavanje će se zaustaviti pri učitavanju svakog DLL-a**. Dakle, kada rundll32 učita vaš DLL, izvršavanje će se zaustaviti.

Ovaj metod zaustavlja izvršavanje pri događajima učitavanja modula, ali je dolazak do entry point-a učitanog DLL-а manje direktan nego u x64dbg postupku ispod.

### Korišćenje x64dbg/x32dbg

- **Učitajte rundll32** (64-bitna verzija se nalazi u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- **Promenite komandnu liniju** (_File --> Change Command Line_) i unesite putanju do DLL-а i funkciju koju želite da pozovete, na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Otvorite _Options --> Settings_ i izaberite "**DLL Entry**".
- Zatim **pokrenite izvršavanje**. Debugger će se zaustaviti na svakom dll main-u i u nekom trenutku će se **zaustaviti na entry point-u vašeg DLL-а**. Odatle samo pronađite mesta na koja želite da postavite breakpoint.

Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, možete da vidite **u kom se kodu nalazite** tako što ćete pogledati **vrh prozora win64dbg-a**:

![Korišćenje IDA-e - Korišćenje x64dbg/x32dbg: Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, možete da vidite u kom se kodu nalazite tako što ćete pogledati vrh prozora win64dbg-a](<../../images/image (842).png>)

Ovaj indikator potvrđuje da je izvršavanje zaustavljeno unutar DLL-а koji želite da debugujete.

## GUI aplikacije / video-igre

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje vrednosti koje su važne u igri koja se izvršava i koje su sačuvane u memoriji, kao i za njihovu izmenu. Više informacija:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end/alат za reverse engineering za GNU Project Debugger (GDB), namenjen igrama. Međutim, može se koristiti za bilo šta u vezi sa reverse engineeringom.

[**Decompiler Explorer**](https://dogbolt.org/) je web front-end za više dekompajlera. Ovaj web servis omogućava poređenje izlaza različitih dekompajlera za male izvršne fajlove.

## Istraga nativnog koda zasnovana na dokazima pomoću REA

**REA** pruža pristup analizama Hopper-а, Ghidra-е i IDA-е putem CLI-ja i MCP-ja. Zahteva Node.js 22.x (najmanje 22.19), 24.x (najmanje 24.11) ili 26+, kao i npm. Najpre konfigurišite postojećeg nativnog provider-а; proverite `rea providers --json` i izričito izaberite provider ako ih više podržava cilj. Umesto `0x1000` u nastavku upotrebite ime funkcije ili adresu uočenu u inventaru.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Počnite od stringa funkcije ili simbola, pratite reference i pozivaoce, a zatim pregledajte dosije izabrane funkcije i pseudokod pomoću `rea decompile`. REA vezuje sesiju za izabranog provajdera, umesto da ga tiho zameni nakon greške. Za ponovljive upite, `--snapshot PATH` ponovo koristi samo bajtove artefakta, provajdera, podešavanja, operaciju i parametre koji se podudaraju; snapshot je lokalni keš, a ne sačuvana baza podataka provajdera. Sačuvajte vraćeni Evidence i eksplicitne nepoznanice, umesto da izvedene putanje ili tekst dekompilatora tretirate kao izvorni kod.<sup>[[16]](#references)[[18]](#references)</sup>

Za JavaScript/Electron ulazne tačke koje vode do native add-on-ova, pogledajte [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Skriptovana analiza u IDA-i i Ghidri pomoću lokalnog TCP bridge-a

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) radi unutar **već otvorene** IDA baze podataka ili Ghidra CodeBrowser programa i omogućava zasebnoj skripti da upituje i menja tu bazu podataka za analizu. Pokrenite `ID_Server.py` iz IDA-inog Python CLI-ja (`import ID_Server`) ili `Ghidra_Server.py` iz Ghidrinog Script Manager-a. IDA se vezuje za `127.0.0.1`, počevši od porta `5073`, i proverava više portove. Trenutna Ghidra skripta počinje od porta `5093` i pokušava deset portova, zaključno sa `5102`; njen Java socket se vezuje za wildcard adresu, a ne samo za loopback. Pre povezivanja proverite port koji je ispisala instanca. Za razliku od headless analyzer-a, ovaj bridge radi nad programom koji je trenutno otvoren u toj GUI instanci.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Šaljite **jednu komandu završenu znakom za novi red po konekciji** i čitajte odgovor završen znakom za novi red. Rezultat je obično JSON. Na primer, nakon što pronađete uvezeni API relevantan za ulaznu putanju, `IMPORTXREF` pronalazi njegova mesta poziva; zatim `DECOMP_XREF` grupno dekompajlira pozivaoce izabrane adrese. `FUNC` pregleda funkciju, dok `PCODE` vraća međureprezentaciju dekompilatora. Koristite adresu iz aktivne baze podataka, a ne adresu prekopiranu iz binarne datoteke sa drugačijom baznom adresom. Primer u nastavku koristi podrazumevani IDA port; za Ghidru koristite port koji je ispisala njena skripta.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Isti kanal može da **izmeni bazu podataka za analizu**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` i `PATCH` menjaju nazive, tipove, definicije struktura, granice funkcija ili sačuvane bajtove. `PATCH` je izmena baze podataka, **a ne** dokaz da je izvršena izmena aktivnog procesa. Nijedan listener ne dokumentuje autentifikaciju. IDA je dostupan samo preko loopback interfejsa, ali Ghidra može biti dostupna preko mrežnih interfejsa; ograničite pristup Ghidra listener-u kada ga koristite. `QUIT` zaustavlja oba listener-a, a IDA takođe izlaže `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugovanje shellcode-a pomoću blobrunner-a

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alocira **shellcode**, ispisuje njegovu **memorijsku adresu** i pauzira izvršavanje.\
Prikačite debugger kao što je IDA ili x64dbg, postavite breakpoint na ispisanu adresu i nastavite izvršavanje da biste debugovali shellcode.

Stranica github-a sa izdanjima sadrži zip arhive sa kompajliranim izdanjima: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Nešto izmenjenu verziju Blobrunner-a možete pronaći na sledećem linku. Da biste je kompajlirali, samo **napravite C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod i izgradite ga**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugovanje shellcode-a pomoću jmp2it-a

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je sličan BlobRunner-u. Alocira shellcode i ulazi u beskonačnu petlju. Prikačite debugger, nastavite izvršavanje na **2–5 sekundi**, pauzirajte unutar te petlje i izvršite step do sledećeg poziva koji prenosi izvršavanje na alocirani shellcode.

![Debugger pauziran u beskonačnoj petlji jmp2it-a, neposredno pre poziva alociranog shellcode-a](<../../images/image (509).png>)

Kompajliranu verziju [jmp2it-a možete preuzeti sa stranice sa izdanjima](https://github.com/adamkramer/jmp2it/releases/).

### Debugovanje shellcode-a pomoću Cutter-a

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI za radare. Cutter-om možete emulirati shellcode i dinamički ga ispitivati.

Imajte na umu da Cutter omogućava „Open File“ i „Open Shellcode“. U mom slučaju, kada sam shellcode otvorio kao datoteku, ispravno ga je dekompilirao, ali kada sam ga otvorio kao shellcode, nije:

![Cutter prikazuje različite rezultate analize kada se isti bajtovi otvore kao datoteka ili kao shellcode](<../../images/image (562).png>)

Da biste pokrenuli emulaciju na željenom mestu, tamo postavite bp i Cutter će je, po svemu sudeći, automatski pokrenuti odatle:

![Postavljanje breakpoint-a na željenu ulaznu tačku shellcode-a pre pokretanja Cutter emulacije](<../../images/image (589).png>)

![Cutter emulator pauziran na izabranom breakpoint-u shellcode-a](<../../images/image (387).png>)

Stek možete, na primer, videti u hex dump-u:

![Prikaz steka emuliranog shellcode-a u Cutter-ovom hex dump-u](<../../images/image (186).png>)

### Uklanjanje obfuskacije shellcode-a i pronalaženje izvršenih funkcija

Trebalo bi da isprobate [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Pokazaće vam, na primer, **koje funkcije** shellcode koristi i da li se shellcode **dekodira** u memoriji.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg takođe dolazi sa grafičkim pokretačem u kojem možete da izaberete željene opcije i izvršite shellcode

![Grafički pokretač scDbg-a za izbor opcija emulacije i praćenja shellcode-a](<../../images/image (258).png>)

Opcija **Create Dump** čuva završni shellcode ako se tokom rada u memoriji dinamički izvrše izmene shellcode-a (korisno za preuzimanje dekodiranog shellcode-a). **start offset** može biti koristan za pokretanje shellcode-a od određene pozicije. Opcija **Debug Shell** korisna je za otklanjanje grešaka u shellcode-u pomoću scDbg terminala (međutim, smatram da su za to bolje bilo koje od prethodno objašnjenih opcija, jer ćete moći da koristite Ida ili x64dbg).

### Disasembliranje pomoću CyberChef-a

Otpremite datoteku shellcode-a kao ulaz i upotrebite sledeći recept da biste je disasemblirali: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Uklanjanje MBA obfuskacije

**Mixed Boolean-Arithmetic (MBA)** obfuskacija skriva jednostavne izraze kao što je `x + y` iza formula koje kombinuju aritmetičke (`+`, `-`, `*`) i bitovne operatore (`&`, `|`, `^`, `~`, shifts). Važno je da su ovi identiteti obično tačni samo uz **modularnu aritmetiku fiksne širine**, pa su prenosi i prekoračenja bitni:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ako ovaj tip izraza pojednostavite generičkim alatom za algebru, lako možete dobiti pogrešan rezultat jer semantika širine bita nije uzeta u obzir.<sup>[[1]](#references)</sup>

### Praktični tok rada

1. **Zadržite originalnu širinu bita** iz lifted koda/IR izlaza/decompiler izlaza (`8/16/32/64` bita).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
   - **Linearni**: ponderisani zbirovi bitovskih atoma
   - **Semilinearni**: linearni izrazi sa konstantnim maskama kao što je `x & 0xFF`
   - **Polinomski**: pojavljuju se proizvodi
   - **Mešoviti**: proizvodi i bitovska logika su isprepletani, često sa ponovljenim podizrazima
3. **Proverite svako potencijalno prepisivanje** nasumičnim testiranjem ili SMT dokazom. Ako se ekvivalentnost ne može dokazati, zadržite originalni izraz umesto da nagađate.

### Zaobiđite spljošteni tok kontrole uskim izvršnim isečkom

Često nije potrebno rekonstruisati kompletan graf toka kontrole. Kod control-flow flattening-a, opaque predicates, velikih dispatcher-a ili koda sa mnogo MBA izraza, pratite reference od šifrovanih blobova i izlaznih bafera do najmanje rutine koja ih transformiše. Zatim reprodukujte samo taj isečak toka podataka ili ga izvršite nezavisno; dispatcher nije deo potrebnog rešenja ako se relevantno stanje može direktno inicijalizovati.<sup>[[7]](#references)</sup>

Praktični tok rada je:<sup>[[7]](#references)</sup>

1. Popišite izvršne i podatkovne sekcije, relokacije i unakrsne reference. Izbacite kandidate za tabele iz `.rodata`, uz očuvanje redosleda bajtova i širine elemenata.
2. Pronađite poslednju rutinu koja upisuje otvoreni tekst ili izlazni bafer. Zabeležite njene ulaze, referencirane tabele, uvezene pozive i potrebno globalno stanje.
3. Prenesite samo te operacije u Python model fiksne širine. Ako isečak i dalje zavisi od previše stanja, pozovite rutinu pomoću Unicorn-а, QEMU-а ili debuggera i zakačite nebitne uvezene funkcije umesto da emulirate ceo program.
4. Potvrdite da extractor zaista izvodi svoj izlaz iz dostavljenog binarnog fajla: uklonite tihe rezervne opcije, pretražite ga u potrazi za ugrađenim odgovorima i pokrenite ga na neviđenim build-ovima sa izmenjenim stringovima, ključevima, identifikatorima, rasporedima i seed-ovima za obfuskaciju.

Korisne komande za prvi prolaz su:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Detektujte MBA izraze koji su prikriveni konstanti

Izraz bajta koji naizgled zavisi od ulaza može potpuno da poništi svoj ulaz. Nakon izdvajanja tabela, evaluirajte izraz u celom 8-bitnom domenu; skup izlaznih vrednosti koji sadrži samo jednu vrednost dokazuje da je taj bajt konstanta, bez potrebe da rekonstrušete okolnu mašinu stanja.<sup>[[7]](#references)</sup>

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

Zadržite završnu masku jer se pri originalnom sabiranju vrednost prelama na širini bajta. Za širi domen, pitajte SMT solver da li je za dva simbolička ulaza iste širine zadovoljivo `f(x1) != f(x2)`: `unsat` dokazuje nepromenljivost, dok `sat` daje kontraprimer i znači da se ulaz ne može odbaciti.<sup>[[7]](#references)</sup>

#### Prepoznajte dekodiranje vezano za okruženje

Provere protiv analize ne moraju da izazovu grananje ili rušenje. Dekoder može da umeša rezultat senzora u bit ključa, konstantu opaque-predicate-a ili stanje spljoštenog dispečera, da nastavi normalno i u emulatoru proizvede uverljiv, ali netačan otvoreni tekst. Zato nije dovoljno zakrpiti samo vidljive grane koje izazivaju grešku; pratite zavisnosti podataka od provera okruženja do stanja dekodera, uporedite isti isečak na autentičnom uređaju i u emulatoru i proverite kako forsiranje rezultata svakog senzora menja konačni bafer.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktičan MBA pojednostavljivač za analizu malvera i reverzni inženjering zaštićenih binarnih datoteka. Klasifikuje izraz i prosleđuje ga kroz specijalizovane tokove obrade, umesto da na sve primenjuje jedan generički prolaz za prepisivanje.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evaluira izraz nad Boolean ulazima, izvodi potpis i istovremeno pokreće nekoliko metoda oporavka, kao što su uparivanje obrazaca, konverzija u ANF i interpolacija koeficijenata.
- **Semilinear MBA**: atomi maskirani konstantama ponovo se sastavljaju rekonstrukcijom podeljenom po bitovima, tako da maskirani regioni ostanu ispravni.
- **Polynomial/Mixed MBA**: proizvodi se rastavljaju na jezgra, a ponovljeni podizrazi mogu se izdvojiti u privremene promenljive pre pojednostavljivanja spoljne relacije.

Primer mešovitog identiteta koji često vredi pokušati oporaviti:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Ovo se može svesti na:

```c
x * y
```

### Beleške o reverse engineeringu

- Prednost dajte pokretanju alata CoBRA nad **lifted IR izrazima** ili izlazom dekompajlera, nakon što izdvojite tačno izračunavanje.
- Koristite `--bitwidth` izričito kada izraz potiče iz maskirane aritmetike ili registara uske širine.
- Ako vam je potreban jači korak dokazivanja, pogledajte lokalne beleške o Z3 ovde:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA dolazi i kao **LLVM pass plugin** (`libCobraPass.so`), što je korisno kada želite da normalizujete LLVM IR sa mnogo MBA izraza pre kasnijih faza analize.
- Nepodržane mešovite rezidualne izraze osetljive na prenos treba shvatiti kao znak da zadržite originalni izraz i ručno analizirate put prenosa.

## Oporavak spljoštavanja toka kontrole sa XOR stanjem

Spljoštivač u OLLVM stilu može da čuva stanje trenutnog osnovnog bloka u dva 64-bitna registra i da ga rekonstruiše pomoću XOR operacije u dispečeru. Svaki originalni blok upisuje par koji predstavlja njegovo sledeće stanje i skače nazad u dispečer. Uslovni blok može da koristi `CMOVcc` za zamenu jedne polovine para u skladu sa CPU zastavicama, pa praćenjem samo vidljivih instrukcija grananja nećete uočiti oba naslednika. Za razliku od dispečera sa indirektnim skokom, ovaj oblik može svuda da koristi direktne povratne grane.<sup>[[19]](#references)[[20]](#references)</sup>

Da biste rekonstruisali graf, pronađite stablo poređenja u dispečeru i dva registra stanja, mapirajte svako upoređeno XOR stanje na ciljni blok, pa pratite upise у пар регистара који стижу до сваког оригиналног блока. Za uslovne upise uključite instrukciju koja postavlja zastavice i oba ishoda `CMOVcc`. Zamenite izlaz iz dispečera svakog bloka njegovim razrešenim direktnim naslednikom ili uslovnim grananjem; tada dispečer postaje nedostižan bez izmena binarnog fajla. Ovo je pristup koji obuhvata ceo CFG; ako vas zanima samo jedan dekoder, gore opisani [workflow uskog execution slice-a](#bypass-flattened-control-flow-with-a-narrow-execution-slice) može biti brži.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatizuje ovaj oblik u Binary Ninja. Kopirajte `plugins/DispatchThis` u korisnički direktorijum za dodatke Binary Ninja i ponovo pokrenite program. Na zahvaćenoj funkciji otvorite **Function Settings** i izaberite `OLLVM_XOR_64`; ako analiza ne počne, upotrebite **Analysis → Reanalyze All Functions**. Ovaj režim prepravlja ivice toka kontrole u MLIL-u, a ne bajtove fajla, i ne zahteva Z3 niti razrešivač indirektnih skokova. Testiran je na Binary Ninja 5.3.9757+; ne uklanja mrtve upise stanja po blokovima, zato ih nemojte pogrešno smatrati preostalim aktivnim prelazima.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuskator zamenjuje operacije programa sekvencama instrukcija zasnovanih na `mov` instrukciji i koristi obradu signala/izuzetaka za izmenu toka kontrole. Detalji:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Za podržane binarne fajlove, [demovfuscator](https://github.com/kirschju/demovfuscator) može da deobfuskira rezultat. Ima nekoliko zavisnosti.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

I [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako igrate **CTF, ovo zaobilazno rešenje za pronalaženje flaga** može biti veoma korisno: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **ulaznu tačku**, pretražite funkcije po `::main`, kao u primeru:

![Pronalaženje ulazne tačke Rust programa u Ghidri pretragom naziva funkcija za dvostruku dvotačku i main](<../../images/image (1080).png>)

U ovom slučaju, binarna datoteka se zvala authenticator, tako da je prilično očigledno da je ovo zanimljiva main funkcija.\
Kada znate **nazive** pozvanih **funkcija**, potražite ih na **Internetu** da biste saznali više o njihovim **ulazima** i **izlazima**.

### Oporavak Rust stringova iz ELF firmware-a

U **Rust ELF** binarnim datotekama, mnogi statički stringovi nisu referencirani kao C pokazivači sa završnim NUL znakom. Uobičajen `rustc` raspored sadrži **torku pokazivača i dužine** unutar **`.data.rel.ro`**, koja upućuje na stvarni string blob smešten u **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

To znači da `strings` ili podrazumevana analiza u Ghidri mogu spojiti susedne stringove ili potpuno propustiti unakrsne reference.<sup>[[3]](#references)</sup>

Brz tok rada:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pronađite virtuelnu adresu i veličinu sekcije **`.rodata`**.
2. Prođite kroz **`.data.rel.ro`** reč po reč.
3. Svaku vrednost unutar opsega adresa sekcije `.rodata` tretirajte kao mogući pokazivač na string.
4. Sledeću reč tretirajte kao moguću dužinu.
5. Primenite filtere za proveru ispravnosti (na primer, zadržite dužine između **4** i **100** bajtova).
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

Ovo je naročito korisno pri reverse engineering-u firmware-a, jer oporavljeni Rust stringovi često otkrivaju **HTTP rute, RPC nazive, log poruke, assertions, imena datoteka, config ključeve, command handlere i logiku povezanu sa autentifikacijom**.

Ako Ghidra propusti te stringove, pokrenite prilagođenu skriptu/plugin koji primenjuje istu heuristiku i kreira string podatke na referenciranim `.rodata` pomerajima. Objavljeni alati `rust-strings` i `RustStrings.py` kompanije Pen Test Partners predstavljaju dobre primere za prilagođavanje ove ideje drugim **veličinama reči, endianness-u i rasporedima sekcija**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Za Delphi kompajlirane binarne datoteke možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako treba da radite reverse engineering Delphi binarne datoteke, preporučio bih vam IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pritisnite **Alt+F7** u IDA-i da učitate Python plugin, a zatim izaberite datoteku plugina.

Ovaj plugin će izvršiti binarnu datoteku i dinamički razrešiti nazive funkcija na početku debugging-a. Kada započnete debugging, ponovo pritisnite dugme Start (zeleno dugme ili f9) i breakpoint će se aktivirati na početku pravog koda.

Ako pritisnete dugme u grafičkoj aplikaciji, debugger može da se zaustavi u funkciji koju je to dugme pozvalo.

## Golang

Za uobičajene Go binarne datoteke, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) može da oporavi runtime strukture i poboljša nazive funkcija u IDA-i. Učitajte njegov Python plugin pomoću **Alt+F7**.

Ako treba da radite reverse engineering Golang binarne datoteke, preporučio bih vam IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pritisnite **Alt+F7** u IDA-i da učitate Python plugin, a zatim izaberite datoteku plugina.

Ovo će razrešiti nazive funkcija.

### Oporavak metapodataka bez tabele simbola

Čak i stripped Go izvršna datoteka i dalje zahteva runtime metapodatke za mapiranje programskih brojača na funkcije. [GoReSym](https://github.com/mandiant/GoReSym) pronalazi i parsira strukture kao što su `pclntab` i `moduledata`, koristeći kod izveden iz Go runtime-a. Tako se mogu oporaviti granice funkcija, nazivi, izvorne putanje, tipovi i detalji o izgradnji bez oslanjanja na uobičajenu tabelu simbola.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuskator može da ostavi te strukture upotrebljivim, a da pritom zameni rekonstruisana imena. Garble, na primer, hešira identifikatore i putanje paketa i uklanja informacije o build-u, modulima i debagovanju.<sup>[[12]](#references)</sup> Token obfuskiranog paketa mora da ostane dosledan u svim funkcijama iz tog paketa. Grupisati funkcije prema ponavljajućem tokenu, zaključiti kom paketu pripadaju na osnovu funkcija koje pozivaju, stringova i API-ja, a zatim primeniti oznaku tog paketa na celu grupu.<sup>[[13]](#references)</sup>

### Rekonstrukcija Garble imena pomoću GoResolver-a

[GoResolver](https://github.com/volexity/GoResolver) kombinuje izdvajanje runtime simbola sa generisanjem čistih referenci i uparivanjem grafa toka kontrole (CFG). Koristite ovaj redosled:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifikujte verziju kompajlera.** Najpre isprobajte `BuildInfo` i ugrađene stringove verzije. Ako ih je obfuskator uklonio, uporedite delove priloženog Go runtime-a sa referentnim runtime-ovima za različite verzije. U Volexity testovima, oko `2%` runtime-a bilo je dovoljno da se razlikuju glavne verzije Go-a. Smatrajte ovo empirijskom optimizacijom, a ne univerzalnim pragom.<sup>[[13]](#references)</sup>
2. **Napravite reference za uparivanje.** Generišite čiste binarne fajlove za identifikovanu verziju Go-a, ciljnu arhitekturu i verovatne biblioteke. Usklađivanje toolchain-a smanjuje razlike u CFG-u koje je uneo kompajler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Uporedite funkcije.** GoGrapher uparuje CFG-ove funkcija i daje normalizovane ocene od `0.0` do `1.0`. Uparivanje osnovnih blokova zasniva se na ponderisanom poređenju sličnih instrukcija. Uparivanja sa visokim stepenom pouzdanosti povezuju nasumično imenovane funkcije sa čistom implementacijom. Slabija uparivanja i dalje mogu da otkriju paket ili modul.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Proverite i uvezite.** Potvrdite predložena imena na osnovu odnosa pozivanja, konstanti, stringova i sporednih efekata, a zatim uvezite JSON izveštaj pomoću GoResolver dodatka za IDA ili Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instalirajte toolchain i pokrenite kombinovani alat za izdvajanje i uparivanje grafova:<sup>[[10]](#references)</sup>

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

Podrazumevani prag značajnog poklapanja je `0.9`. Opcije `--extract` i `--graph` mogu da izdvoje bilo koju fazu, dok se podrazumevano pokreću obe jer se oporavljeni metapodaci runtime-a i dokazi iz CFG-a međusobno dopunjuju.<sup>[[10]](#references)</sup> CFG ocene su heurističke: inlining, build zastavice, arhitektura i razlike među verzijama biblioteka mogu da promene oblik grafa, zato sačuvajte nerazrešene funkcije umesto da im dodeljujete nazive uz malo pouzdanja.<sup>[[13]](#references)</sup>

### Oporavak Go tabele stringova

Go binarne datoteke smeštaju bajtove stringova iz svih povezanih paketa u jednu neprekidnu tabelu. Unosi nisu završeni NUL bajtom, a strukture runtime-a ne otkrivaju osnovnu adresu ni veličinu tabele. Međutim, kompajler raspoređuje unose prvo po dužini, a zatim po abecedi, na svim operativnim sistemima i arhitekturama. Zato analitičar, nakon što pronađe jedan unos, može da pregleda susedne unose i pomoću unakrsnih referenci podataka poveže stringove sa kodom.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatizuje ovaj postupak u IDA Pro i Ghidra. Najpre sačekajte da se automatska analiza završi, jer se dodatak oslanja na unakrsne reference segmenata podataka. Podrazumevana početna tačka je runtime string `entersyscall`, nakon čega dodatak može da pretražuje u oba smera, definiše oporavljene stringove u bazi podataka i izveze JSON mapiranje stringova na funkcije koje ih referenciraju.<sup>[[14]](#references)</sup>

Filtrirajte izveštaj prema paketu funkcije koja referencira string da biste razdvojili kod aplikacije ili malvera od šuma povezanih biblioteka. Ova tehnika ne može da oporavi literale uništene obfuskacijom, kao što je Garbleova transformacija `-literals`. I dalje može da organizuje runtime stringove koji su ostali neobfuskirani.<sup>[[14]](#references)[[15]](#references)</sup>

### Oporavak Go runtime tipova

Go ugrađuje informacije o runtime tipovima koje koriste funkcije kao što je garbage collection. Kada su informacije o build-u uklonjene ili disassembler ne parsira ove metapodatke, može delovati kao da instrukcije učitavaju proizvoljne adrese podataka, a ciljna oblast ostaje bez tipa. Oporavak metapodataka pretvara te adrese u čitljive reference na tipove i olakšava razumevanje mogućnosti paketa.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) može da izdvoji simbole i parsira runtime tipove u JSON izveštaj. Trenutni CLI koristi podkomandu `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Opcija `-y`/`--types` omogućava parsiranje tipova. Uvezite izveštaj pomoću GoResolver dodatka za IDA Pro ili Ghidra da biste definisali oporavljene tipove i primenili njihove reference u bazi podataka analize. U formatu izveštaja uvedenom ovom funkcijom, ako izostavite `-y`, članovi RTTI adrese i oporavljenih tipova ostaju null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver podržava PE, ELF i Mach-O uzorke za x86, AMD64, ARM i ARM64, tako da se isti postupak može primeniti na Go binarne fajlove za Windows, Linux i macOS.<sup>[[10]](#references)</sup>

## Kompajlirani Python

Na ovoj stranici možete pronaći kako da dobijete Python kod iz ELF/EXE binarnog fajla kompajliranog iz Pythona:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ako dobijete **binarni fajl** GBA igre, možete koristiti različite alate da biste je **emulirali** i **debugovali**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite debug verziju_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra dodatak
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra dodatak

U programu [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_** ** možete videti kako da pritisnete dugmad na Game Boy Advance konzoli.

![no$gba konfiguracija kontrola koja prikazuje mapiranje dugmadi za Game Boy Advance](<../../images/image (581).png>)

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

Dakle, u ovoj vrsti programa zanimljivo je **kako program obrađuje korisnički unos**. Na adresi **0x4000130** pronaći ćete često korišćenu funkciju: **KEYINPUT**.

![Prikaz Ghidra-e GBA binarne datoteke koja upućuje na KEYINPUT na adresi 0x4000130](<../../images/image (447).png>)

Na prethodnoj slici možete videti da se funkcija poziva iz **FUN_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekoliko inicijalizacijskih operacija (koje nisu bitne):

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

Poslednji if proverava da li se **`uVar4`** nalazi u **prethodnom skupu Keys** i nije trenutni taster, što se naziva otpuštanjem tastera (trenutni taster je sačuvan u **`uVar1`**).

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

- Prvo se poredi sa **vrednošću 4** (dugme **SELECT**): u ovom izazovu ovo dugme briše ekran.
- Zatim se vrednost poredi sa **8** (dugme **START**); u ovom izazovu se tom putanjom proverava da li je uneti kod validan.
  - U ovom slučaju, varijabla **`DAT_030000d8`** poredi se sa 0xf3 i, ako su vrednosti jednake, izvršava se određeni kod.
- U svim ostalim slučajevima proverava se i uvećava brojač (`DAT_030000d4`).\
  Dok je brojač manji od 8, vrednosti pritisnutih tastera sabiraju se u `DAT_030000d8`.

Dakle, u ovom izazovu, znajući vrednosti dugmadi, trebalo je **pritisnuti kombinaciju kraću od 8 dugmadi čiji zbir iznosi 0xf3.**

**Izvor za ovaj tutorijal:** [arhivirani opis rešenja izazova Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursevi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Deobfuskacija binarnih datoteka)

## References

- [1] [Pojednostavljivanje MBA obfuskacije pomoću CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repozitorijum](https://github.com/trailofbits/CoBRA)
- [3] [Dekodiranje Rust stringova - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - Rust stringovi](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - vodič za reverse engineering GBA igara (arhiviran)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Pobeda nad reverse engineeringom uz pomoć AI-ja, ili barem pokušaj](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Pristup poređenju grafova toka kontrole zasnovan na uparivanju osnovnih blokova](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repozitorijum](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mehanizam obfuskacije Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Korišćenje sličnosti grafova toka kontrole za automatsku deobfuskaciju Golang binarnih datoteka](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repozitorijum](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Novosti u Volexity Golang alatima](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Obrnuti inženjering bilo čega](https://github.com/morluto/rea)
- [17] [REA analiza upravljanog koda](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA vodič za CLI i dokaze](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Tok rada za uklanjanje spljoštavanja toka kontrole u Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF zero-day upad, Java loader, web shell i AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementacija IDA bridge servera](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementacija Ghidra bridge servera](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) se vezuje za wildcard adresu](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
