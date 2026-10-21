# Alati za reverse engineering i osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## Alati za reverse engineering zasnovani na ImGui

Softver:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automatizacija WinDbg-a u korisničkom režimu

{{#ref}}
windbg-automation.md
{{#endref}}

## Debugovanje Windows kernela

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Na mreži:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) za **decompile** iz wasm (binarni format) u wat (čitljiv tekst)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) za **compile** iz wat u wasm
- Možete isprobati i [web-wasmdec](https://wwwg.github.io/web-wasmdec/) za dekompilaciju.

Softver:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Keširani bajtkod Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtuelizovani payload-i i prilagođene VM-ove

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je decompiler koji **dekompajlira i pregleda više formata**, uključujući **biblioteke** (.dll), **datoteke metapodataka za Windows** (.winmd) i **izvršne datoteke** (.exe). Nakon dekompilacije, assembly se može sačuvati kao Visual Studio projekat (.csproj).

Prednost je u tome što, ako je potrebno obnoviti izgubljeni izvorni kod iz legacy assembly-ja, ovaj postupak može uštedeti vreme. Pored toga, dotPeek omogućava praktičnu navigaciju kroz dekompilisani kod, što ga čini jednim od savršenih alata za **analizu Xamarin algoritama.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Zahvaljujući sveobuhvatnom modelu dodataka i API-ju koji omogućava prilagođavanje alata vašim potrebama, .NET Reflector štedi vreme i pojednostavljuje razvoj. Pogledajmo mnoštvo usluga reverse engineering-a koje ovaj alat pruža:

- Omogućava uvid u to kako podaci prolaze kroz biblioteku ili komponentu
- Omogućava uvid u implementaciju i upotrebu .NET jezika i okvira
- Pronalazi nedokumentiranu i neizloženu funkcionalnost kako biste bolje iskoristili API-je i korišćene tehnologije.
- Pronalazi zavisnosti i različite assembly-je
- Locira tačno mesto grešaka u vašem kodu, komponentama trećih strana i bibliotekama.
- Omogućava debugovanje izvornog koda za sav .NET kod sa kojim radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy dodatak za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga instalirati direktno iz VSCode-a, nema potrebe da preuzimate git. Kliknite na **Extensions** i **potražite ILSpy**).\
Ako treba da **decompile**, **modify** i ponovo **recompile**, možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegov aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Desni klik -> Modify Method** da biste nešto izmenili unutar funkcije).

### Pregled upravljanog koda bez izvršavanja pomoću REA

**REA** može da pregleda PE/CLI metapodatke i CIL bez učitavanja assembly-ja. Počnite od identiteta artefakta, a zatim pregledajte članove i deklarisane granice izvornog koda; ovo je korisno pri proveri sumnjivih poziva pre korišćenja decompiler-a ili pokretanja programa.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Za poređenje verzija, `compare_managed_members` koristi identitet sirovog CIL-a/potpisa i otiske dekodiranih instrukcija, umesto da tretira tokene metapodataka kao stabilne između buildova. Deklaracija P/Invoke nije dokaz da je native kod pokrenut; `verify_managed_native_boundaries` zahteva odgovarajući native export ili dokaz funkcije da bi proverio tu granicu. Sačuvajte digest artefakta, MVID i nerazrešena mapiranja uz rezultat.<sup>[[17]](#references)</sup>

### Evidentiranje u DNSpy

Da bi **DNSpy beležio neke informacije u datoteku**, možete da koristite ovaj isečak:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Da biste debagovali kod pomoću DNSpy-ja, potrebno je da:

Najpre promenite **Assembly attributes** koji se odnose na **debugging**:

![DNSpy Logging - DNSpy Debugging: Najpre promenite Assembly attributes koji se odnose na debugging](<../../images/image (973).png>)

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

Zatim kliknite na **compile**:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Zatim sačuvajte novu datoteku pomoću _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Ovo je neophodno jer će se u suprotnom tokom **izvršavanja** na kod primeniti nekoliko **optimizacija**, pa je moguće da se tokom otklanjanja grešaka **tačka prekida nikada ne aktivira** ili da neke **promenljive ne postoje**.

Zatim, ako vašu .NET aplikaciju **pokreće** **IIS**, možete je **restartovati** pomoću:

```
iisreset /noforce
```

Zatim, da biste započeli debugovanje, zatvorite sve otvorene fajlove, a u kartici **Debug** izaberite **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste započeli debugovanje, zatvorite sve otvorene fajlove, a u kartici Debug izaberite Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste se povezali sa **IIS serverom** i kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste se povezali sa IIS serverom i kliknite na attach](<../../images/image (113).png>)

Pošto sada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Najpre kliknite na _Debug >> Break All_, a zatim na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Pošto sada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Najpre kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Pošto sada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Najpre kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u prozoru **Modules** i izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u prozoru Modules i izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom miša na bilo koji modul u **Assembly Explorer** i izaberite **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom miša na bilo koji modul u Assembly Explorer i izaberite Sort Assemblies](<../../images/image (339).png>)

## Java dekompajler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugovanje DLL-ova

### Korišćenje IDA-e

- **Učitajte rundll32** (64-bitna verzija se nalazi na C:\Windows\System32\rundll32.exe, a 32-bitna na C:\Windows\SysWOW64\rundll32.exe)
- Izaberite debugger **Windbg**
- Izaberite "**Suspend on library load/unload**"

![Debugovanje DLL-ova - Korišćenje IDA-e: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Podesite **parametre** izvršavanja tako što ćete uneti **putanju do DLL-a** i funkciju koju želite da pozovete:

![Debugovanje DLL-ova - Korišćenje IDA-e: Podesite parametre izvršavanja tako što ćete uneti putanju do DLL-a i funkciju koju želite da pozovete](<../../images/image (704).png>)

Kada započnete debugovanje, **izvršavanje će se zaustaviti pri učitavanju svakog DLL-a**. Dakle, kada rundll32 učita vaš DLL, izvršavanje će se zaustaviti.

Ovaj metod zaustavlja izvršavanje pri događajima učitavanja modula, ali dolazak do ulazne tačke učitanog DLL-a nije tako direktan kao u x64dbg postupku u nastavku.

### Korišćenje x64dbg/x32dbg

- **Učitajte rundll32** (64-bitna verzija se nalazi na C:\Windows\System32\rundll32.exe, a 32-bitna na C:\Windows\SysWOW64\rundll32.exe)
- **Promenite komandnu liniju** ( _File --> Change Command Line_ ) i unesite putanju do DLL-a i funkciju koju želite da pozovete, na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Otvorite _Options --> Settings_ i izaberite "**DLL Entry**".
- Zatim **pokrenite izvršavanje**. Debugger će se zaustaviti pri svakoj DLL main funkciji, a u nekom trenutku će se **zaustaviti na ulaznoj tački vašeg DLL-a**. Odatle samo potražite mesta na koja želite da postavite breakpoint.

Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, možete da vidite **u kom se kodu nalazite** tako što ćete pogledati **vrh prozora win64dbg-a**:

![Korišćenje IDA-e - Korišćenje x64dbg/x32dbg: Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, možete da vidite u kom se kodu nalazite tako što ćete pogledati vrh prozora win64dbg-a](<../../images/image (842).png>)

Ovaj indikator potvrđuje da se izvršavanje zaustavilo unutar DLL-a koji želite da debugujete.

## GUI aplikacije / videoigre

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje mesta na kojima se važne vrednosti čuvaju u memoriji pokrenute igre i njihovu izmenu. Više informacija:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end/alat za reverse engineering za GNU Project Debugger (GDB), namenjen igrama. Međutim, može se koristiti za bilo šta povezano sa reverse engineeringom.

[**Decompiler Explorer**](https://dogbolt.org/) je web front-end za više dekompajlera. Ovaj web servis omogućava poređenje izlaza različitih dekompajlera za male izvršne fajlove.

## Istraga nativnog koda potkrepljena dokazima pomoću REA

**REA** omogućava pristup Hopper, Ghidra i IDA analizama putem CLI-ja i MCP-a. Potrebni su Node.js 22.x (najmanje 22.19), 24.x (najmanje 24.11) ili 26+, kao i npm. Najpre konfigurišite postojeći nativni provider; proverite `rea providers --json` i izričito izaberite provider ako ih više podržava cilj. U nastavku zamenite `0x1000` opaženim nazivom funkcije ili adresom iz inventara.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Počnite od stringa funkcije ili simbola, pratite reference i pozivače, a zatim pregledajte dosije izabrane funkcije i pseudokod pomoću `rea decompile`. REA vezuje sesiju za izabranog pružaoca, umesto da ga neprimetno zameni nakon greške. Za ponovljive upite, `--snapshot PATH` ponovo koristi samo bajtove artefakata, pružaoca, podešavanja, operaciju i parametre koji se podudaraju; snapshot je lokalni keš, a ne sačuvana baza podataka pružaoca. Sačuvajte vraćeni Evidence i eksplicitno navedene nepoznanice, umesto da izvedene putanje ili tekst dekompilatora tretirate kao izvorni kod.<sup>[[16]](#references)[[18]](#references)</sup>

Za ulazne tačke JavaScript/Electron koje vode do nativnih dodataka, pogledajte [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Skriptovana analiza IDA i Ghidra pomoću lokalnog TCP mosta

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) radi unutar već otvorene baze podataka IDA ili programa CodeBrowser u Ghidra i omogućava zasebnoj skripti da šalje upite toj bazi analize i menja je. Pokrenite `ID_Server.py` iz IDA-inog Python CLI-ja (`import ID_Server`) ili `Ghidra_Server.py` iz Ghidra Script Manager-a. IDA se vezuje za `127.0.0.1`, počevši od porta `5073`, i proverava više portove. Trenutna Ghidra skripta počinje od porta `5093` i pokušava deset portova, sve do `5102`; njen Java socket se vezuje za wildcard adresu, a ne samo za loopback. Pre povezivanja proverite port koji ispisuje instanca. Za razliku od headless analyzer-a, ovaj most radi sa programom koji je trenutno otvoren u toj GUI instanci.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Šaljite **jednu komandu završenu znakom za novi red po konekciji** i čitajte odgovor završen znakom za novi red. Rezultat je obično JSON. Na primer, nakon što pronađete uvezeni API relevantan za ulaznu putanju, `IMPORTXREF` pronalazi njegova mesta poziva; zatim `DECOMP_XREF` grupno dekompilira pozivače izabrane adrese. `FUNC` pregleda funkciju, dok `PCODE` vraća međureprezentaciju dekompilatora. Koristite adresu iz aktivne baze podataka, a ne adresu kopiranu iz drugačije rebazovanog binarnog fajla. Primer ispod koristi podrazumevani port IDA; za Ghidra koristite port koji ispisuje njena skripta.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Isti kanal može da **izmeni bazu podataka za analizu**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` i `PATCH` menjaju nazive, tipove, definicije struktura, granice funkcija ili sačuvane bajtove. `PATCH` je izmena baze podataka, **a ne** dokaz da je izvršena izmena procesa uživo. Nijedan listener ne dokumentuje autentifikaciju. IDA je dostupan samo preko loopback interfejsa, ali Ghidra može biti dostupna preko mrežnih interfejsa; ograničite pristup Ghidra listeneru kada ga koristite. `QUIT` zaustavlja oba listenera, a IDA takođe izlaže `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging shellcode-a pomoću blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alocira **shellcode**, ispisuje njegovu **memorijsku adresu** i pauzira izvršavanje.\
Prikačite debugger kao što je IDA ili x64dbg, postavite breakpoint na ispisanu adresu i nastavite izvršavanje da biste debugovali shellcode.

GitHub stranica sa izdanjima sadrži ZIP fajlove sa kompajliranim izdanjima: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blago izmenjenu verziju Blobrunner-a možete pronaći na sledećem linku. Da biste je kompajlirali, samo **napravite C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod, pa ga izgradite**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging shellcode-a pomoću jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je sličan BlobRunner-u. Alocira shellcode i ulazi u beskonačnu petlju. Prikačite debugger, nastavite izvršavanje na **2–5 sekundi**, pauzirajte unutar te petlje i iskoračite do sledećeg poziva koji prenosi izvršavanje na alocirani shellcode.

![Debugger je pauziran u beskonačnoj petlji jmp2it-a, neposredno pre poziva alociranog shellcode-a](<../../images/image (509).png>)

Kompajliranu verziju [jmp2it-a možete preuzeti na stranici sa izdanjima](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode-a pomoću Cutter-a

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI za radare. Pomoću Cutter-a možete emulirati shellcode i dinamički ga ispitivati.

Imajte na umu da Cutter omogućava opcije „Open File“ i „Open Shellcode“. U mom slučaju, kada sam otvorio shellcode kao fajl, ispravno ga je dekompilirao, ali kada sam ga otvorio kao shellcode, nije:

![Cutter prikazuje različite rezultate analize kada se isti bajtovi otvore kao fajl ili kao shellcode](<../../images/image (562).png>)

Da biste pokrenuli emulaciju na željenom mestu, postavite bp na to mesto i Cutter će, po svemu sudeći, automatski pokrenuti emulaciju odatle:

![Postavljanje breakpoint-a na željenu ulaznu tačku shellcode-a pre pokretanja Cutter emulacije](<../../images/image (589).png>)

![Cutter emulator je pauziran na izabranom breakpoint-u shellcode-a](<../../images/image (387).png>)

Možete, na primer, da vidite stack u hex dump-u:

![Prikaz emuliranog stack-a shellcode-a u Cutter-ovom hex dump-u](<../../images/image (186).png>)

### Deobfuskacija shellcode-a i pronalaženje izvršenih funkcija

Probajte [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Prikazaće vam stvari kao što su **koje funkcije** shellcode koristi i da li se shellcode **dekodira** u memoriji.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg takođe ima grafički pokretač u kom možete da izaberete željene opcije i izvršite shellcode

![scDbg grafički pokretač za izbor opcija za emulaciju i praćenje shellcode-a](<../../images/image (258).png>)

Opcija **Create Dump** pravi dump konačnog shellcode-a ako je došlo do bilo kakve dinamičke izmene shellcode-a u memoriji (korisno za preuzimanje dekodiranog shellcode-a). **start offset** može biti koristan za pokretanje shellcode-a od određenog offset-a. Opcija **Debug Shell** korisna je za debagovanje shellcode-a pomoću scDbg terminala (međutim, smatram da je bilo koja od prethodno objašnjenih opcija bolja za tu namenu, jer ćete moći da koristite IDA ili x64dbg).

### Disasembliranje pomoću CyberChef-a

Otpremite datoteku sa shellcode-om kao ulaz i upotrebite sledeći recept da biste ga disasemblirali: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Uklanjanje MBA obfuskacije

**Mixed Boolean-Arithmetic (MBA) obfuscation** skriva jednostavne izraze kao što je `x + y` pomoću formula koje kombinuju aritmetičke operatore (`+`, `-`, `*`) i bitovske operatore (`&`, `|`, `^`, `~`, pomeranja). Važno je to što su ovi identiteti obično tačni samo pri **modularnoj aritmetici fiksne širine**, pa su prenosi i prekoračenja bitni:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ako pojednostavite ovu vrstu izraza pomoću generičkih alata za algebru, lako možete dobiti pogrešan rezultat jer semantika širine bitova nije uzeta u obzir.<sup>[[1]](#references)</sup>

### Praktični tok rada

1. **Zadržite originalnu širinu bitova** iz izlaza podignutog koda/IR-a/dekompilatora (`8/16/32/64` bita).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
   - **Linearni**: ponderisani zbirovi bitovskih atoma
   - **Semilinearni**: linearni izraz plus konstantne maske, kao što je `x & 0xFF`
   - **Polinomski**: pojavljuju se proizvodi
   - **Mešoviti**: proizvodi i bitovska logika su isprepletani, često uz ponovljene podizraze
3. **Proverite svaku predloženu transformaciju** nasumičnim testiranjem ili SMT dokazom. Ako se ekvivalentnost ne može dokazati, zadržite originalni izraz umesto da nagađate.

### Zaobilaženje spljoštenog toka kontrole pomoću uskog isečka izvršavanja

Često nije potrebno rekonstruisati kompletan graf toka kontrole. Kod spljoštavanja toka kontrole, neprozirnih predikata, velikih dispečera ili koda sa mnogo MBA izraza, pratite reference od šifrovanih blobova i izlaznih bafera do najmanje rutine koja ih transformiše. Zatim reprodukujte samo taj isečak toka podataka ili ga izvršite nezavisno; dispečer nije deo potrebnog rešenja ako se relevantno stanje može direktno inicijalizovati.<sup>[[7]](#references)</sup>

Praktični tok rada je:<sup>[[7]](#references)</sup>

1. Popišite izvršne i podatkovne sekcije, relokacije i unakrsne reference. Izdvojite potencijalne tabele iz `.rodata`, čuvajući redosled bajtova i širinu elemenata.
2. Identifikujte poslednju rutinu koja upisuje otvoreni tekst ili izlazni bafer. Zabeležite njene ulaze, referencirane tabele, uvezene pozive i potrebno globalno stanje.
3. Podignite samo te operacije u Python model fiksne širine. Ako isečak i dalje zavisi od previše stanja, pozovite rutinu pomoću Unicorn-a, QEMU-a ili debagera i zakačite nebitne uvezene funkcije umesto da emulirate ceo program.
4. Potvrdite da ekstraktor zaista izvodi svoj izlaz iz dostavljenog binarnog fajla: uklonite tihe rezervne putanje, pretražite ga u potrazi za ugrađenim odgovorima i pokrenite ga na neviđenim verzijama sa izmenjenim stringovima, ključevima, identifikatorima, rasporedima i seed-ovima za obfuskaciju.

Korisne komande za prvi prolaz su:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Otkrivanje MBA izraza koji su prikriveni konstanti

Izraz nad bajtovima koji naizgled zavisi od ulaza može u potpunosti poništiti svoj ulaz. Nakon izdvajanja tabela, evaluirajte izraz nad celim 8-bitnim domenom; skup izlaznih vrednosti koji sadrži samo jedan element dokazuje da je taj bajt konstanta, bez potrebe za rekonstrukcijom okolne mašine stanja.<sup>[[7]](#references)</sup>

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

Zadržite završnu masku jer originalno sabiranje ima prelivanje širine bajta. Za širi domen pitajte SMT solver da li je `f(x1) != f(x2)` zadovoljivo za dva simbolička ulaza iste širine: `unsat` dokazuje invarijantnost, dok `sat` daje protivprimer i znači da se ulaz ne može odbaciti.<sup>[[7]](#references)</sup>

#### Prepoznajte dekodiranje vezano za okruženje

Provere protiv analize ne moraju da izazovu grananje ili pad programa. Dekoder može da uklopi rezultat senzora u bit ključa, konstantu opaque-predicate-a ili stanje spljoštenog dispečera, da nastavi normalno i u emulatoru proizvede uverljiv, ali netačan otvoreni tekst. Zato nije dovoljno zakrpiti samo vidljive grane koje izazivaju grešku; pratite zavisnosti podataka od provera okruženja do stanja dekodera, uporedite isti slice na autentičnom uređaju i emulatoru i proverite kako forsiranje rezultata svakog senzora menja završni bafer.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktičan MBA simplifier za analizu malware-a i reverse engineering zaštićenih binarnih datoteka. Klasifikuje izraz i prosleđuje ga specijalizovanim pipeline-ovima, umesto da na sve primenjuje jedan generički prolaz za prepisivanje.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evaluira izraz nad Booleovim ulazima, izvodi potpis i upoređuje nekoliko metoda oporavka, kao što su prepoznavanje obrazaca, ANF konverzija i interpolacija koeficijenata.
- **Semilinear MBA**: atomi sa konstantnom maskom ponovo se grade pomoću rekonstrukcije podeljene po bitovima, tako da maskirane oblasti ostanu ispravne.
- **Polynomial/Mixed MBA**: proizvodi se rastavljaju na jezgra, a ponovljeni podizrazi mogu se izdvojiti u privremene promenljive pre pojednostavljivanja spoljašnje relacije.

Primer mešanog identiteta koji često vredi pokušati rekonstruisati:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Ovo se može svesti na:

```c
x * y
```

### Beleške o reverznom inženjerstvu

- Prednost dajte pokretanju CoBRA nad **izrazima lifted IR-a** ili izlazom decompiler-a nakon što izolujete tačno izračunavanje.
- Eksplicitno koristite `--bitwidth` kada izraz potiče iz maskirane aritmetike ili registara užeg opsega.
- Ako vam je potreban snažniji korak dokazivanja, pogledajte lokalne beleške o Z3 ovde:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA se isporučuje i kao **dodatak za LLVM pass** (`libCobraPass.so`), što je korisno kada želite da normalizujete LLVM IR sa mnogo MBA operacija pre kasnijih passes za analizu.
- Nepodržane mešovite reziduale osetljive na prenos treba tretirati kao signal da zadržite originalni izraz i ručno razmotrite putanju prenosa.

## Rekonstrukcija XOR-state spljoštavanja toka upravljanja

OLLVM-style flattener može da čuva stanje trenutnog osnovnog bloka u dva 64-bitna registra i da ga rekonstruiše pomoću XOR-a u dispatcher-u. Svaki originalni blok upisuje par koji predstavlja njegovo sledeće stanje i skače nazad na dispatcher. Uslovni blok može da koristi `CMOVcc` za zamenu jedne polovine para u skladu sa CPU zastavicama, pa praćenje samo vidljivih instrukcija grananja propušta dva nasledna bloka. Za razliku od dispatcher-a sa indirektnim skokom, ovaj oblik može svuda da koristi direktne povratne ivice.<sup>[[19]](#references)[[20]](#references)</sup>

Da biste rekonstruisali graf, identifikujte stablo poređenja dispatcher-a i dva registra stanja, mapirajte svako poređeno XOR stanje na ciljni blok, a zatim pratite prethodne upise u par registara u svakom originalnom bloku. Kod uslovnih upisa uključite instrukciju koja postavlja zastavice i oba ishoda `CMOVcc`. Prepišite izlaz dispatcher-a svakog bloka u njegov razrešeni direktni nasledni blok ili uslovno grananje; dispatcher tada postaje nedostižan bez menjanja binarne datoteke. Ovo je pristup koji obuhvata ceo CFG; ako je važan samo jedan decoder, [workflow za uski izvršni isečak](#bypass-flattened-control-flow-with-a-narrow-execution-slice) iznad može biti brži.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatizuje ovaj oblik u Binary Ninja. Kopirajte `plugins/DispatchThis` u direktorijum korisničkih dodataka za Binary Ninja i ponovo pokrenite program. Na zahvaćenoj funkciji otvorite **Function Settings** i izaberite `OLLVM_XOR_64`; ako analiza ne počne, izaberite **Analysis → Reanalyze All Functions**. Ovaj režim prepisuje MLIL ivice toka upravljanja, a ne bajtove datoteke, i ne zahteva Z3 ni resolver za indirektne skokove. Testiran je na Binary Ninja 5.3.9757+; ne uklanja mrtve upise stanja u svakom bloku, pa ih nemojte pomešati sa preostalim aktivnim prelazima.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuscator zamenjuje programske operacije nizovima instrukcija zasnovanih na `mov` i koristi obradu signala/izuzetaka za izmenu toka upravljanja. Više detalja:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Za podržane binarne datoteke, [demovfuscator](https://github.com/kirschju/demovfuscator) može da deobfuscira rezultat. Ima nekoliko zavisnosti.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

I instalirajte [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako učestvujete u **CTF-u, ovo zaobilažno rešenje za pronalaženje flag-a** može biti veoma korisno: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **entry point**, pretražite funkcije po `::main`, kao u primeru:

![Pronalaženje Rust entry point-a u Ghidra-i pretraživanjem imena funkcija po dvostrukoj dvotački i main](<../../images/image (1080).png>)

U ovom slučaju, binarni fajl se zvao authenticator, pa je prilično očigledno da je ovo zanimljiva main funkcija.\
Kada saznate **imena** **funkcija** koje se pozivaju, potražite ih na **Internetu** da biste saznali koji su njihovi **ulazi** i **izlazi**.

### Vraćanje Rust stringova iz ELF firmware-a

U **Rust ELF** binarnim fajlovima, mnoge statičke stringove ne referenciraju pokazivači sa NUL-terminacijom u C stilu. Uobičajen `rustc` raspored koristi **torku pokazivača i dužine** unutar **`.data.rel.ro`**, koja pokazuje na stvarni string blob smešten u **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

To znači da `strings` ili podrazumevana Ghidra analiza mogu da spoje susedne stringove ili u potpunosti previde unakrsne reference.<sup>[[3]](#references)</sup>

Brzi tok rada:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pronađite virtuelnu adresu i veličinu sekcije **`.rodata`**.
2. Nabrojte stavke u **`.data.rel.ro`** jednu reč po jednu.
3. Svaku vrednost unutar adresnog opsega `.rodata` tretirajte kao mogući pokazivač na string.
4. Sledeću reč tretirajte kao moguću dužinu.
5. Primenite provere razumnosti (na primer, zadržite dužine između **4** i **100** bajtova).
6. Pročitajte tačno `length` bajtova iz `.rodata` umesto da pretražujete do `0x00`.

Minimalna logika ekstraktora:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Ovo je naročito korisno pri reverse engineeringu firmware-a, jer pronađeni Rust stringovi često otkrivaju **HTTP rute, RPC nazive, log poruke, assertion-e, nazive datoteka, konfiguracione ključeve, command handlere i logiku povezanu sa autentifikacijom**.

Ako Ghidra ne pronađe te stringove, pokrenite prilagođenu skriptu/plugin koji primenjuje istu heuristiku i kreira string podatke na referenciranim `.rodata` offsetima. Objavljeni alati `rust-strings` i `RustStrings.py` kompanije Pen Test Partners dobra su polazna tačka za prilagođavanje te ideje drugim **veličinama reči, endianness-u i rasporedima sekcija**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Za binarne datoteke kompajlirane iz Delphi koda možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako treba da radite reverse engineering Delphi binarne datoteke, predlažem da koristite IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pritisnite **Alt+F7** u IDA-i da učitate Python plugin, a zatim izaberite datoteku plugina.

Ovaj plugin će izvršiti binarnu datoteku i dinamički razrešiti nazive funkcija na početku debugginga. Kada debugging počne, ponovo pritisnite dugme Start (zeleno dugme ili f9) i breakpoint će se aktivirati na početku stvarnog koda.

Ako pritisnete dugme u grafičkoj aplikaciji, debugger može da se zaustavi u funkciji koju to dugme poziva.

## Golang

Za uobičajene Go binarne datoteke, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) može da pronađe runtime strukture i poboljša nazive funkcija u IDA-i. Učitajte njegov Python plugin pomoću **Alt+F7**.

Ako treba da radite reverse engineering Go binarne datoteke, predlažem da koristite IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pritisnite **Alt+F7** u IDA-i da učitate Python plugin, a zatim izaberite datoteku plugina.

Ovim će se razrešiti nazivi funkcija.

### Oporavak metapodataka bez tabele simbola

Čak i stripped Go izvršna datoteka mora da sadrži runtime metapodatke za mapiranje programskih brojača na funkcije. [GoReSym](https://github.com/mandiant/GoReSym) pronalazi i parsira strukture kao što su `pclntab` i `moduledata` koristeći kod izveden iz Go runtime-a. Tako se mogu oporaviti granice funkcija, nazivi, putanje do izvornog koda, tipovi i detalji o build-u bez oslanjanja na konvencionalnu tabelu simbola.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuskator može da ostavi te strukture upotrebljivim, a da zameni oporavljena imena. Garble, na primer, hešira identifikatore i putanje paketa i uklanja informacije o build-u, modulima i debugovanju.<sup>[[12]](#references)</sup> Token obfuskiranog paketa mora da ostane isti u svim funkcijama iz tog paketa. Grupisanje funkcija prema ponavljajućem tokenu, zaključite koji je paket na osnovu njegovih pozvanih funkcija, stringova i API-ja, pa zatim prenesite oznaku paketa na celu grupu.<sup>[[13]](#references)</sup>

### Oporavite Garble imena pomoću GoResolver-a

[GoResolver](https://github.com/volexity/GoResolver) objedinjuje izdvajanje runtime simbola, generisanje čistih referenci i uparivanje grafova toka kontrole (CFG). Koristite sledeći redosled:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifikujte verziju kompajlera.** Prvo probajte `BuildInfo` i ugrađene stringove verzije. Ako ih je obfuskator uklonio, uporedite delove priloženog Go runtime-a sa referentnim runtime-ovima za poznate verzije. U Volexity testovima, oko `2%` runtime-a bilo je dovoljno za razlikovanje glavnih verzija Go-a. Ovo posmatrajte kao empirijsku optimizaciju, a ne kao univerzalni prag.<sup>[[13]](#references)</sup>
2. **Pripremite odgovarajuće reference.** Generišite čiste binarne datoteke za identifikovanu verziju Go-a, ciljnu arhitekturu i verovatne biblioteke. Usklađivanje toolchain-a smanjuje razlike u CFG-u koje stvara kompajler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Uporedite funkcije.** GoGrapher uparuje CFG-ove funkcija i daje normalizovane ocene u rasponu od `0.0` do `1.0`. Uparivanje osnovnih blokova zasniva se na ponderisanom poređenju sličnih instrukcija. Uparivanja sa visokim stepenom pouzdanosti mapiraju nasumično imenovane funkcije na čistu implementaciju. Slabija uparivanja i dalje mogu da identifikuju paket ili modul.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Potvrdite i uvezite.** Potvrdite predložena imena pomoću odnosa pozivanja, konstanti, stringova i sporednih efekata, a zatim uvezite JSON izveštaj pomoću GoResolver plugin-a za IDA ili Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Podrazumevani prag značajnog poklapanja je `0.9`. Prekidači `--extract` i `--graph` mogu da izdvoje bilo koju od faza, dok se podrazumevano pokreću obe jer se oporavljeni runtime metapodaci i dokazi iz CFG-a međusobno dopunjuju.<sup>[[10]](#references)</sup> CFG rezultati su heuristički: inlining, build zastavice, arhitektura i razlike u verzijama biblioteka mogu da promene oblik grafa, zato sačuvajte nerazrešene funkcije umesto da im dodeljujete nazive sa niskim stepenom pouzdanosti.<sup>[[13]](#references)</sup>

### Oporavak Go string tabele

Go binarne datoteke smeštaju bajtove stringova iz svakog povezanog paketa u jednu neprekidnu tabelu. Stavke se ne završavaju NUL bajtom, a runtime strukture ne otkrivaju početnu adresu ni veličinu tabele. Međutim, kompajler raspoređuje stavke prvo po dužini, a zatim abecedno, na svim operativnim sistemima i arhitekturama. Zato analitičar, nakon što pronađe jednu stavku, može da prođe kroz susedne stavke i pomoću unakrsnih referenci podataka poveže stringove sa kodom.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatizuje ovaj postupak u IDA Pro i Ghidra. Najpre sačekajte da se završi automatska analiza jer se dodatak oslanja na unakrsne reference u segmentu podataka. Podrazumevana sidrena vrednost je runtime string `entersyscall`, nakon čega dodatak može da skenira u oba smera, definiše oporavljene stringove u bazi podataka i izveze JSON mapiranje stringova i funkcija koje ih referenciraju.<sup>[[14]](#references)</sup>

Filtrirajte izveštaj prema paketu funkcije koja referencira string da biste razdvojili kod aplikacije ili malware-a od šuma povezanih biblioteka. Ovom tehnikom nije moguće oporaviti literale koje je uništila obfuskacija, kao što je Garbleova transformacija `-literals`. I dalje može da posluži za organizovanje runtime stringova koji su ostali neobfuskirani.<sup>[[14]](#references)[[15]](#references)</sup>

### Oporavak Go runtime tipova

Go ugrađuje informacije o runtime tipovima koje koriste funkcije kao što je garbage collection. Kada su build informacije uklonjene ili disassembler ne raščlanjuje ove metapodatke, može izgledati da instrukcije učitavaju proizvoljne adrese podataka, a ciljna oblast ostaje bez tipova. Oporavak metapodataka pretvara te adrese u čitljive reference na tipove i olakšava razumevanje mogućnosti paketa.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) može da izdvoji simbole i raščlani runtime tipove u JSON izveštaj. Trenutni CLI koristi podkomandu `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Opcija `-y`/`--types` omogućava parsiranje tipova. Uvezite izveštaj pomoću GoResolver-ovog dodatka za IDA Pro ili Ghidra da biste definisali oporavljene tipove i primenili njihove reference u bazi podataka analize. U formatu izveštaja uvedenom ovom funkcijom, ako izostavite `-y`, članovi RTTI adrese i oporavljenih tipova ostaju null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver podržava PE, ELF i Mach-O uzorke za x86, AMD64, ARM i ARM64, pa se isti postupak primenjuje na Go binarne datoteke za Windows, Linux i macOS.<sup>[[10]](#references)</sup>

## Kompajlirani Python

Na ovoj stranici možete pronaći kako da dobijete Python kod iz ELF/EXE binarne datoteke kompajlirane iz Python koda:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ako dobijete **binarnu datoteku** GBA igre, možete da koristite različite alate za njenu **emulaciju** i **debugovanje**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite verziju za debugovanje_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Dodatak za Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Dodatak za Ghidra

U [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_** ** možete videti kako da pritisnete **dugmad** na Game Boy Advance konzoli

![Konfiguracija kontrola u no$gba prikazuje raspored dugmadi na Game Boy Advance konzoli](<../../images/image (581).png>)

Kada se pritisne, svaki **taster ima vrednost** po kojoj se prepoznaje:

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

Dakle, u ovakvoj vrsti programa zanimljiv deo biće **način na koji program obrađuje korisnički unos**. Na adresi **0x4000130** pronaći ćete često prisutnu funkciju: **KEYINPUT**.

![Ghidra prikaz GBA binarne datoteke koja upućuje na KEYINPUT na adresi 0x4000130](<../../images/image (447).png>)

Na prethodnoj slici možete videti da se funkcija poziva iz **FUN_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekoliko init operacija (koje nisu važne):

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

Pronađen je sledeći kod:

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

Poslednji if proverava da li se **`uVar4`** nalazi među **poslednjim tasterima** i nije trenutni taster, što se takođe naziva otpuštanjem dugmeta (trenutni taster se čuva u **`uVar1`**).

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

U prethodnom kodu možete videti da se **uVar1** (mesto na kom se nalazi **vrednost pritisnutog dugmeta**) poredi sa nekim vrednostima:

- Prvo se poredi sa **vrednošću 4** (dugme **SELECT**): u ovom izazovu ovo dugme briše ekran.
- Zatim se vrednost poredi sa **8** (dugme **START**); u ovom izazovu se tom putanjom proverava da li je uneti kod ispravan.
  - U tom slučaju se varijabla **`DAT_030000d8`** poredi sa vrednošću 0xf3 i, ako su vrednosti jednake, izvršava se određeni kod.
- U svim ostalim slučajevima proverava se i uvećava brojač (`DAT_030000d4`).\
  Dok je brojač manji od 8, vrednosti pritisnutih dugmadi sabiraju se u `DAT_030000d8`.

Dakle, u ovom izazovu, pošto znate vrednosti dugmadi, trebalo je da **pritisnete kombinaciju kraću od 8 dugmadi čiji je zbir 0xf3.**

**Izvor za ovaj vodič:** [arhivirani opis izazova Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursevi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Deobfuskacija binarnih fajlova)

## References

- [1] [Pojednostavljivanje MBA obfuskacije pomoću CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [CoBRA repozitorijum Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Dekodiranje Rust stringova - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - vodič za GBA reversing (arhiviran)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Pobeda nad AI-potpomognutim reverse engineering-om ili barem pokušaj](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Pristup poređenju grafova toka kontrole zasnovan na uparivanju osnovnih blokova](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repozitorijum](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mehanizam obfuskacije Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Korišćenje sličnosti grafova toka kontrole za automatsku deobfuskaciju Golang binarnih fajlova](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repozitorijum](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Ažuriranja Volexity Golang alata](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverzno inženjerstvo svega](https://github.com/morluto/rea)
- [17] [REA analiza upravljanog koda](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI i vodič za dokaze](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: tok rada za uklanjanje izravnavanja toka kontrole u Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: upad u PaperCut MF putem zero-day ranjivosti, Java loader, web shell i AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementacija IDA bridge servera](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementacija Ghidra bridge servera](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) se vezuje za džoker adresu](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
