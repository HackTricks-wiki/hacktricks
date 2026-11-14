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

## Otklanjanje grešaka u Windows kernel-u

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm dekompajler / Wat kompajler

Onlajn:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) da **dekompajlirate** wasm (binarni) u wat (čitljiv tekst)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) da **kompajlirate** wat u wasm
- Za dekompajliranje možete isprobati i [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Softver:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Keširani bajtkod u Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtuelizovani payload-i i prilagođene VM mašine

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET dekompajler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je dekompajler koji **dekompajlira i pregleda više formata**, uključujući **biblioteke** (.dll), **datoteke Windows metapodataka** (.winmd) i **izvršne datoteke** (.exe). Nakon dekompajliranja, sklop se može sačuvati kao Visual Studio projekat (.csproj).

Ovo je korisno ako je potrebno obnoviti izgubljeni izvorni kôd iz zastarelog sklopa, jer taj postupak može uštedeti vreme. Pored toga, dotPeek omogućava praktično kretanje kroz dekompajlirani kôd, što ga čini jednim od idealnih alata za **analizu Xamarin algoritama.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Uz sveobuhvatan model dodataka i API koji proširuje alat kako bi odgovarao vašim potrebama, .NET Reflector štedi vreme i pojednostavljuje razvoj. Pogledajmo mnoštvo usluga za reverse engineering koje ovaj alat pruža:

- Pruža uvid u to kako podaci prolaze kroz biblioteku ili komponentu
- Pruža uvid u implementaciju i upotrebu .NET jezika i okvira
- Pronalaženje nedokumentovanih i neprikazanih funkcionalnosti radi boljeg iskorišćavanja korišćenih API-ja i tehnologija
- Pronalaženje zavisnosti i različitih sklopova
- Pronalaženje tačne lokacije grešaka u vašem kodu, komponentama trećih strana i bibliotekama
- Otklanjanje grešaka u izvornom kodu celokupnog .NET koda s kojim radite

### [ILSpy](https://github.com/icsharpcode/ILSpy) i [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy dodatak za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga instalirati direktno iz VSCode-a; nije potrebno preuzimanje sa git-a. Kliknite na **Extensions** i **potražite ILSpy**).\
Ako treba da **dekompajlirate**, **izmenite** i ponovo **kompajlirate**, možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegovu aktivno održavanu izvedenicu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Desni klik -> Modify Method** da biste promenili nešto unutar funkcije).

### Pregled upravljanog koda bez izvršavanja pomoću REA

**REA** može da pregleda PE/CLI metapodatke i CIL bez učitavanja sklopa. Počnite od identiteta artefakta, a zatim pregledajte članove i deklarisane granice izvornog koda; ovo je korisno pri proveri sumnjivih poziva pre upotrebe dekompajlera ili pokretanja programa.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Za poređenje verzija, `compare_managed_members` koristi sirovi identitet CIL/signature i fingerprintove dekodiranih instrukcija, umesto da tretira metadata tokene kao stabilne između buildova. P/Invoke deklaracija nije dokaz da je izvršen native kod; `verify_managed_native_boundaries` zahteva odgovarajući native export ili function Evidence da bi proverio tu granicu. Sačuvaj digest artefakta, MVID i nerazrešena mapiranja uz rezultat.<sup>[[17]](#references)</sup>

### Evidentiranje u DNSpy

Da bi **DNSpy zapisivao neke informacije u datoteku**, možeš da upotrebiš ovaj isečak:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy otklanjanje grešaka

Da biste otklanjali greške u kodu pomoću DNSpy-ja, potrebno je da:

Najpre promenite **atribute sklopa** koji se odnose na **otklanjanje grešaka**:

![DNSpy evidentiranje - DNSpy otklanjanje grešaka: Najpre promenite atribute sklopa koji se odnose na otklanjanje grešaka](<../../images/image (973).png>)

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

Zatim sačuvajte novu datoteku pomoću _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Zatim sačuvajte novu datoteku pomoću File Save module](<../../images/image (602).png>)

Ovo je neophodno jer će se, ako to ne uradite, tokom **runtime**-a na kod primeniti nekoliko **optimizacija**, pa je moguće da se tokom debagovanja **break-point nikada ne aktivira** ili da neke **promenljive ne postoje**.

Zatim, ako vašu .NET aplikaciju pokreće **IIS**, možete je **restartovati** pomoću:

```
iisreset /noforce
```

Zatim, da biste počeli s otklanjanjem grešaka, zatvorite sve otvorene datoteke, pa na kartici **Debug Tab** izaberite **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste počeli s otklanjanjem grešaka, zatvorite sve otvorene datoteke, pa na kartici Debug Tab izaberite Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste se povezali sa **IIS serverom** i kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste se povezali sa IIS serverom i kliknite na attach](<../../images/image (113).png>)

Sada kada otklanjamo greške u procesu, zaustavite ga i učitajte sve module. Najpre kliknite na _Debug >> Break All_, a zatim na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sada kada otklanjamo greške u procesu, zaustavite ga i učitajte sve module. Najpre kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sada kada otklanjamo greške u procesu, zaustavite ga i učitajte sve module. Najpre kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u prozoru **Modules**, pa izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u prozoru Modules, pa izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom miša na bilo koji modul u **Assembly Explorer** i izaberite **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom miša na bilo koji modul u Assembly Explorer i izaberite Sort Assemblies](<../../images/image (339).png>)

## Java dekompajler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Otklanjanje grešaka u DLL-ovima

### Korišćenje IDA-e

- **Učitajte rundll32** (64-bitna verzija je u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- Izaberite debugger **Windbg**
- Izaberite "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Podesite **parametre** izvršavanja tako što ćete navesti **putanju do DLL-a** i funkciju koju želite da pozovete:

![Debugging DLLs - Using IDA: Podesite parametre izvršavanja tako što ćete navesti putanju do DLL-a i funkciju koju želite da pozovete](<../../images/image (704).png>)

Kada započnete otklanjanje grešaka, **izvršavanje će se zaustaviti pri učitavanju svake DLL datoteke**. Zatim, kada rundll32 učita vaš DLL, izvršavanje će se zaustaviti.

Ovaj metod se zaustavlja pri događajima učitavanja modula, ali dolazak do ulazne tačke učitanog DLL-a manje je direktan nego u x64dbg postupku ispod.

### Korišćenje x64dbg/x32dbg

- **Učitajte rundll32** (64-bitna verzija je u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- **Promenite komandnu liniju** ( _File --> Change Command Line_ ) i navedite putanju do DLL-a i funkciju koju želite da pozovete. Na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Otvorite _Options --> Settings_ i izaberite "**DLL Entry**".
- Zatim **pokrenite izvršavanje**. Debugger će se zaustaviti pri svakom pozivu dll main; u nekom trenutku **zaustavićete se na ulaznoj tački svog DLL-a**. Odatle pronađite mesta na koja želite da postavite breakpoint.

Imajte na umu da u win64dbg-u, kada se izvršavanje zaustavi iz bilo kog razloga, možete videti **u kom se kodu nalazite** pri **vrhu prozora win64dbg-a**:

![Using IDA - Using x64dbg/x32dbg: Imajte na umu da u win64dbg-u, kada se izvršavanje zaustavi iz bilo kog razloga, možete videti u kom se kodu nalazite pri vrhu prozora win64dbg-a](<../../images/image (842).png>)

Ovaj indikator potvrđuje da je izvršavanje zaustavljeno unutar DLL-a koji želite da otklanjate.

## GUI aplikacije / video-igre

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje važnih vrednosti koje se čuvaju u memoriji pokrenute igre i njihovu izmenu. Više informacija:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end/reverse engineering alat za GNU Project Debugger (GDB), namenjen prvenstveno igrama. Ipak, može se koristiti za bilo kakve poslove povezane sa reverse engineeringom.

[**Decompiler Explorer**](https://dogbolt.org/) je web front-end za više dekompajlera. Ova web usluga omogućava poređenje izlaza različitih dekompajlera za male izvršne datoteke.

### Dešifrovanje Godot PCK datoteka i oporavak projekta

Za distribuiranu Godot igru pronađite njen PCK u samostalnoj `.pck` datoteci, paketu dodatom izvršnoj datoteci ili ugrađenom u nju, odnosno u direktorijumu `assets` APK-a. [gore](https://github.com/figurophobia/gore) može da pregleda i izdvoji paket, dok je za potpunu rekonstrukciju skripti i resursa potreban GDRE Tools (`gore setup` ga instalira, a možete koristiti i `--gdre`). Ovaj alat podržava Godot 4.x PCK formate v2–v4 za ovaj postupak; može da prepozna zaglavlja v1, ali je za v1 neophodan dostavljeni ključ.<sup>[[25]](#references)</sup>

Automatski oporavak ključa zahteva šifrovanu tabelu datoteka; ako je šifrovan samo sadržaj datoteka, navedite poznati ključ. Neuspešan oporavak ne dokazuje da paket nije šifrovan.<sup>[[28]](#references)</sup>

Pretraga ključa **nije napad na AES-256 prostor ključeva**. Šifrovana tabela datoteka otkriva MD5 vrednost otvorenog teksta, njegovu dužinu, IV i AES-256-CFB šifrat.<sup>[[27]](#references)</sup> `gore` proverava 32-bajtne segmente izvršne datoteke igre ili susednih datoteka kao potencijalne ključeve. Kandidati se filtriraju prema verovatnoj dužini dešifrovane putanje i njenom prefiksu, a pogoci pronađeni binarnim pretraživanjem potvrđuju se dešifrovanjem cele tabele i proverom njenog MD5-a.<sup>[[26]](#references)[[28]](#references)</sup> Najpre pretražuje inicijalizovane odeljke podataka PE/ELF datoteka, a zatim, ako je potrebno, celu datoteku; `--scan` dodaje druge datoteke za proveru.<sup>[[28]](#references)</sup>

Ako se ne pronađe ugrađeni ključ, isprobava se mala ugrađena lista lozinki; opcija `--wordlist` omogućava da navedete druge kandidate. Svaka lozinka se proverava kao zapis ključa izveden iz lozinke koji koristi engine, kao doslovna vrednost dopunjena nulama ili kao ključ od 64 heksadecimalna znaka. Za razliku od pogodaka pronađenih binarnim pretraživanjem, pogoci iz wordlist-a u ovoj implementaciji prolaze samo proveru strukture putanje. Potvrdite ih tako što ćete otvoriti paket i proveriti izdvojene resurse.<sup>[[26]](#references)[[28]](#references)</sup>

Kada je artefakt igre dostupan lokalno, izaberite fazu koja vam je potrebna za analizu. `recover` poziva GDRE radi rekonstrukcije projekta koji se može otvoriti, dok `extract` samo raspakuje sirove datoteke. `key` ispisuje mogući ključ za korišćenje u drugom alatu.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Istraga native koda potkrepljena dokazima uz REA

**REA** omogućava analizu u Hopper-u, Ghidra-i i IDA-i putem CLI-ja i MCP-a. Potrebni su Node.js 22.x (najmanje 22.19), 24.x (najmanje 24.11) ili 26+, kao i npm. Najpre konfigurišite postojeći native provider; proverite `rea providers --json` i izričito izaberite provider ako više njih podržava cilj. Umesto `0x1000` u nastavku upotrebite naziv funkcije ili adresu iz inventara.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Počnite od stringa funkcije ili simbola, pratite reference i pozivače, a zatim pregledajte dosije odabrane funkcije i pseudokod pomoću `rea decompile`. REA vezuje sesiju za odabranog provajdera, umesto da ga neprimetno zameni nakon greške. Za ponovljive upite, `--snapshot PATH` ponovo koristi samo bajtove artefakta, provajdera, podešavanja, operaciju i parametre koji se poklapaju; snapshot je lokalni keš, a ne sačuvana baza podataka provajdera. Sačuvajte vraćeni Evidence i izričito navedene nepoznanice, umesto da izvedene putanje ili tekst dekompilatora tretirate kao izvorni kod.<sup>[[16]](#references)[[18]](#references)</sup>

Za JavaScript/Electron ulazne tačke koje vode do native dodataka pogledajte [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Skriptovana analiza u IDA-i i Ghidri pomoću lokalnog TCP mosta

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) pokreće se unutar **već otvorene** IDA baze podataka ili Ghidra CodeBrowser programa i omogućava zasebnoj skripti da upituje i menja tu bazu analize. Pokrenite `ID_Server.py` iz IDA Python CLI-ja (`import ID_Server`) ili `Ghidra_Server.py` iz Ghidra Script Manager-a. IDA se vezuje za `127.0.0.1`, počevši od porta `5073`, i proverava naredne portove. Trenutna Ghidra skripta počinje od porta `5093` i isprobava deset portova, sve do `5102`; njen Java socket se vezuje za wildcard adresu, a ne samo za loopback. Pre povezivanja proverite port koji je prikazala instanca. Za razliku od headless analyzer-a, ovaj most radi nad programom koji je trenutno otvoren u toj GUI instanci.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Šaljite **po jednu komandu završenu znakom za novi red po vezi** i čitajte odgovor završen znakom za novi red. Rezultat je obično JSON. Na primer, nakon pronalaženja uvezene API funkcije relevantne za ulaznu putanju, `IMPORTXREF` pronalazi mesta njenih poziva; zatim `DECOMP_XREF` grupno dekompajlira pozivače odabrane adrese. `FUNC` pregleda funkciju, dok `PCODE` vraća međureprezentaciju dekompilatora. Koristite adresu iz aktivne baze podataka, a ne adresu prekopiranu iz binarnog fajla sa drugačijom baznom adresom. Primer ispod koristi podrazumevani IDA port; za Ghidru koristite port koji je prikazala njena skripta.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Isti kanal može da **menja bazu podataka za analizu**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` i `PATCH` menjaju nazive, tipove, definicije struktura, granice funkcija ili sačuvane bajtove. `PATCH` je izmena baze podataka, **a ne** dokaz da je primenjena izmena u živom procesu. Nijedan listener ne dokumentuje autentifikaciju. IDA je ograničen na loopback, ali Ghidra može biti dostupan preko mrežnih interfejsa; ograničite pristup Ghidra listener-u kada ga koristite. `QUIT` zaustavlja bilo koji od listener-a, a IDA takođe izlaže `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugovanje shellcode-a pomoću blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alocira **shellcode**, ispisuje njegovu **memorijsku adresu** i pauzira izvršavanje.\
Prikačite debugger, kao što su IDA ili x64dbg, postavite breakpoint na ispisanu adresu i nastavite izvršavanje da biste debugovali shellcode.

Na GitHub stranici izdanja nalaze se ZIP datoteke sa kompajliranim izdanjima: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blago izmenjenu verziju Blobrunner-a možete pronaći na sledećem linku. Da biste je kompajlirali, samo **napravite C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod i izgradite projekat**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugovanje shellcode-a pomoću jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je sličan BlobRunner-u. Alocira shellcode i ulazi u beskonačnu petlju. Prikačite debugger, nastavite izvršavanje na **2–5 sekundi**, pauzirajte unutar te petlje, a zatim izvršavajte korak po korak do narednog poziva koji prenosi izvršavanje na alocirani shellcode.

![Debugger pauziran u beskonačnoj petlji jmp2it-a, neposredno pre poziva alociranog shellcode-a](<../../images/image (509).png>)

Kompajliranu verziju [jmp2it-a možete preuzeti sa stranice izdanja](https://github.com/adamkramer/jmp2it/releases/).

### Debugovanje shellcode-a pomoću Cutter-a

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI za radare. Pomoću Cutter-a možete emulirati shellcode i dinamički ga pregledati.

Imajte na umu da Cutter omogućava „Open File“ i „Open Shellcode“. U mom slučaju, kada sam otvorio shellcode kao datoteku, ispravno ga je dekompilirao, ali kada sam ga otvorio kao shellcode, nije:

![Cutter prikazuje različite rezultate analize pri otvaranju istih bajtova kao datoteke ili kao shellcode-a](<../../images/image (562).png>)

Da biste pokrenuli emulaciju na željenom mestu, postavite bp tamo i Cutter će je, izgleda, automatski pokrenuti od te tačke:

![Postavljanje breakpoint-a na željenu ulaznu tačku shellcode-a pre pokretanja Cutter emulacije](<../../images/image (589).png>)

![Cutter emulator pauziran na izabranom breakpoint-u shellcode-a](<../../images/image (387).png>)

Na primer, stek možete pregledati unutar hex dump-a:

![Prikaz emuliranog steka shellcode-a u Cutter-ovom hex dump-u](<../../images/image (186).png>)

### Deobfuskacija shellcode-a i pronalaženje izvršenih funkcija

Trebalo bi da probate [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Prikazaće vam, na primer, **koje funkcije** shellcode koristi i da li se **dekodira** u memoriji.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg takođe dolazi sa grafičkim pokretačem, u kom možete da izaberete željene opcije i izvršite shellcode

![Grafički pokretač scDbg-a za izbor opcija emulacije i praćenja shellcode-a](<../../images/image (258).png>)

Opcija **Create Dump** izbacuje konačni shellcode ako je došlo do bilo kakve dinamičke izmene shellcode-a u memoriji (korisno za preuzimanje dekodiranog shellcode-a). **start offset** može biti koristan za pokretanje shellcode-a od određenog pomeraja. Opcija **Debug Shell** korisna je za debagovanje shellcode-a pomoću scDbg terminala (međutim, smatram da su za to bolje bilo koje od prethodno objašnjenih opcija, jer ćete moći da koristite Ida ili x64dbg).

### Disasembliranje pomoću CyberChef-a

Otpremite svoju shellcode datoteku kao ulaz i upotrebite sledeći recept da biste je dekompilirali: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskacija MBA obfuscation-a

**Mixed Boolean-Arithmetic (MBA)** obfuscation skriva jednostavne izraze kao što je `x + y` iza formula koje kombinuju aritmetičke operatore (`+`, `-`, `*`) i bitovske operatore (`&`, `|`, `^`, `~`, pomeranja). Važno je da su ovi identiteti obično tačni samo u okviru **modularne aritmetike fiksne širine**, pa su prenos i prekoračenja bitni:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ako pojednostavite izraz ove vrste pomoću generičkih alata za algebru, lako možete dobiti pogrešan rezultat jer semantika širine bitova nije uzeta u obzir.<sup>[[1]](#references)</sup>

### Praktični tok rada

1. **Zadržite originalnu širinu bitova** iz podignutog koda/IR izlaza/dekompilatora (`8/16/32/64` bita).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
   - **Linearan**: ponderisani zbirovi bitovskih atoma
   - **Semilinearan**: linearni izraz plus konstantne maske poput `x & 0xFF`
   - **Polinomski**: pojavljuju se proizvodi
   - **Mešovit**: proizvodi i bitovska logika su isprepleteni, često uz ponavljajuće podizraze
3. **Proverite svako predloženo preuređivanje** nasumičnim testiranjem ili SMT dokazom. Ako se ekvivalencija ne može dokazati, zadržite originalni izraz umesto da nagađate.

### Zaobiđite spljošteni kontrolni tok uskim isečkom izvršavanja

Često nije potrebno rekonstruisati kompletan graf toka kontrole. Kod spljoštavanja toka kontrole, neprozirnih predikata, velikih dispatcher-a ili koda sa mnogo MBA izraza, pratite reference od šifrovanih blokova podataka i izlaznih bafera do najmanje rutine koja ih transformiše. Zatim reprodukujte samo taj isečak toka podataka ili ga izvršite nezavisno; dispatcher nije deo potrebnog rešenja ako se relevantno stanje može direktno inicijalizovati.<sup>[[7]](#references)</sup>

Praktični tok rada je:<sup>[[7]](#references)</sup>

1. Popišite izvršne i podatkovne sekcije, relokacije i unakrsne reference. Izvucite kandidate za tabele iz `.rodata`, uz očuvanje redosleda bajtova i širine elemenata.
2. Pronađite poslednju rutinu koja upisuje otvoreni tekst ili izlazni bafer. Zabeležite njene ulaze, referencirane tabele, uvezene pozive i potrebno globalno stanje.
3. Prenesite samo te operacije u Python model sa fiksnom širinom. Ako isečak i dalje zavisi od previše stanja, pozovite rutinu u Unicorn-u, QEMU-u ili debugger-u i postavite hook-ove za nebitne uvezene funkcije, umesto da emuliрате ceo program.
4. Potvrdite da extractor zaista izvodi svoj izlaz iz dostavljenog binarnog fajla: uklonite tihe fallback-ove, pretražite ga u potrazi za ugrađenim odgovorima i testirajte ga na neviđenim build-ovima sa izmenjenim stringovima, ključevima, identifikatorima, rasporedima i seed-ovima za obfuskaciju.

Korisne naredbe za prvi prolaz su:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Otkrivanje MBA izraza koji su maskirane konstante

Izraz koji naizgled zavisi od ulaza može potpuno da poništi svoj ulaz. Nakon izdvajanja tabela, izračunajte izraz za ceo 8-bitni domen; skup izlaza sa jednim elementom dokazuje da je taj bajt konstanta, bez potrebe za rekonstrukcijom okolne mašine stanja.<sup>[[7]](#references)</sup>

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

Zadržite završnu masku jer originalno sabiranje ima prelivanje ograničeno na širinu bajta. Za širi domen pitajte SMT solver da li je `f(x1) != f(x2)` zadovoljivo za dva simbolička ulaza iste širine: `unsat` dokazuje nepromenljivost, dok `sat` daje kontraprimer i znači da se ulaz ne može odbaciti.<sup>[[7]](#references)</sup>

#### Prepoznajte dekodiranje vezano za okruženje

Provere protiv analize ne moraju da izazovu grananje ili pad programa. Dekoder može da pomeša rezultat senzora u bit ključa, konstantu neprozirnog predikata ili stanje spljoštenog dispečera, da nastavi normalno i u emulatoru proizvede uverljiv, ali netačan otvoreni tekst. Zato nije dovoljno zakrpiti samo vidljive grane koje izazivaju grešku; pratite zavisnosti podataka od sondi okruženja do stanja dekodera, uporedite isti isečak na autentičnom uređaju i emulatoru i testirajte kako forsiranje rezultata svakog senzora menja konačni bafer.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktičan MBA pojednostavljivač za analizu malware-a i reverzno inženjerstvo zaštićenih binarnih datoteka. Klasifikuje izraz i usmerava ga kroz specijalizovane tokove obrade umesto da na sve primenjuje jedan generički prolaz za prepisivanje.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evaluira izraz nad Bulovim ulazima, izvodi potpis i pokreće trku između nekoliko metoda za oporavak, kao što su pattern matching, ANF konverzija i interpolacija koeficijenata.
- **Semilinear MBA**: atomi maskirani konstantama ponovo se izgrađuju rekonstrukcijom podeljenom po bitovima, tako da maskirani regioni ostanu ispravni.
- **Polynomial/Mixed MBA**: proizvodi se rastavljaju na jezgra, a ponovljeni podizrazi mogu se izdvojiti u privremene promenljive pre pojednostavljivanja spoljašnje relacije.

Primer mešovitog identiteta čiji oporavak često vredi pokušati:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Ovo se može svesti na:

```c
x * y
```

### Napomene o reverse engineeringu

- Prednost dajte pokretanju CoBRA nad **lifted IR izrazima** ili izlazom dekompilatora nakon što izdvojite tačan proračun.
- Eksplicitno koristite `--bitwidth` ako izraz potiče iz maskirane aritmetike ili registara uske širine.
- Ako vam je potreban snažniji korak dokazivanja, pogledajte lokalne Z3 napomene ovde:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA dolazi i kao **LLVM pass plugin** (`libCobraPass.so`), što je korisno kada želite da normalizujete LLVM IR sa mnogo MBA operacija pre kasnijih prolaza analize.
- Nepodržane ostatke mešovitih domena osetljive na prenos treba smatrati signalom da zadržite originalni izraz i ručno analizirate putanju prenosa.

## Rekonstrukcija control-flow flattening-a sa XOR stanjem

Obfuscator u OLLVM stilu može čuvati stanje trenutnog osnovnog bloka u dva 64-bitna registra i rekonstruisati ga pomoću XOR operacije u dispatcher-u. Svaki originalni blok upisuje par za sledeće stanje i skače nazad u dispatcher. Uslovni blok može koristiti `CMOVcc` da zameni jednu polovinu para na osnovu CPU zastavica, pa praćenje samo vidljivih instrukcija grananja propušta dva moguća sledbenika. Za razliku od dispatcher-a sa indirektnim skokom, ovaj oblik može koristiti direktne povratne skokove svuda.<sup>[[19]](#references)[[20]](#references)</sup>

Da biste rekonstruisali graf, identifikujte stablo poređenja dispatcher-a i dva registra stanja, mapirajte svako upoređeno XOR stanje na ciljni blok, a zatim pratite upise u par registara koji mogu stići do svakog originalnog bloka. Za uslovne upise uključite instrukciju koja postavlja zastavice i oba ishoda `CMOVcc`. Zamenite izlaz dispatcher-a iz svakog bloka odgovarajućim direktnim sledbenikom ili uslovnim grananjem; nakon toga dispatcher postaje nedostižan bez izmena binarne datoteke. Ovo je pristup zasnovan na kompletnom CFG-u; ako je važan samo jedan decoder, [workflow sa uskim execution slice-om](#bypass-flattened-control-flow-with-a-narrow-execution-slice) iznad može biti brži.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatizuje ovaj oblik u Binary Ninja. Kopirajte `plugins/DispatchThis` u korisnički direktorijum dodataka za Binary Ninja i ponovo pokrenite program. Na funkciji na koju se ovo odnosi otvorite **Function Settings** i izaberite `OLLVM_XOR_64`; ako analiza ne počne, upotrebite **Analysis → Reanalyze All Functions**. Ovaj režim prepisuje MLIL kontrolno-usmerene ivice, a ne bajtove datoteke, i ne zahteva Z3 niti razrešivač indirektnih skokova. Isproban je u Binary Ninja 5.3.9757+; ne uklanja neaktivne upise stanja po blokovima, zato ih nemojte pomešati sa preostalim aktivnim prelazima.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuscator zamenjuje operacije programa sekvencama instrukcija zasnovanim na `mov` i koristi obradu signala/izuzetaka za izmenu toka kontrole. Detalje potražite ovde:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Za podržane binarne datoteke, [demovfuscator](https://github.com/kirschju/demovfuscator) može da deobfuskuje rezultat. Ima nekoliko zavisnosti.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

I [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako igrate **CTF, ovo zaobilazno rešenje za pronalaženje flag-a** može biti veoma korisno: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **ulaznu tačku**, pretražite funkcije po `::main`, kao u primeru:

![Pronalaženje ulazne tačke Rust programa u Ghidri pretragom naziva funkcija za dvotačku-dvotačku main](<../../images/image (1080).png>)

U ovom slučaju binarni fajl se zvao authenticator, tako da je prilično očigledno da je ovo zanimljiva main funkcija.\
Kada saznate **nazive** pozivanih **funkcija**, pretražite ih na **Internetu** da biste saznali više o njihovim **ulazima** i **izlazima**.

### Vraćanje Rust stringova iz ELF firmware-a

U **Rust ELF** binarnim fajlovima, mnogi statički stringovi nisu referencirani kao C-style pokazivači koji se završavaju sa NUL. Čest `rustc` raspored je **torka pokazivača i dužine** unutar **`.data.rel.ro`** koja pokazuje na stvarni string blob smešten u **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

To znači da `strings` ili podrazumevana analiza u Ghidri mogu spojiti susedne stringove ili potpuno propustiti unakrsne reference.<sup>[[3]](#references)</sup>

Brzi postupak:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pronađite virtuelnu adresu i veličinu sekcije **`.rodata`**.
2. Nabrojte vrednosti u sekciji **`.data.rel.ro`**, reč po reč.
3. Svaku vrednost unutar opsega adresa sekcije `.rodata` tretirajte kao kandidatski pokazivač na string.
4. Sledeću reč tretirajte kao kandidatsku dužinu.
5. Primijenite filtere za proveru ispravnosti (na primer, zadržite dužine između **4** i **100** bajtova).
6. Pročitajte tačno `length` bajtova iz `.rodata` umesto da skenirate dok ne naiđete na `0x00`.

Minimalna logika ekstraktora:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Ovo je naročito korisno pri reverse engineering-u firmware-a, jer pronađeni Rust stringovi često otkrivaju **HTTP rute, RPC nazive, log poruke, assertion-e, nazive fajlova, config ključeve, command handlere i logiku povezanu sa autentifikacijom**.

Ako Ghidra ne pronađe te stringove, pokrenite custom script/plugin koji primenjuje istu heuristiku i kreira string podatke na referenciranim `.rodata` offset-ima. Objavljeni alati `rust-strings` i `RustStrings.py` kompanije Pen Test Partners dobra su referenca za prilagođavanje ove ideje drugim **veličinama reči, redosledima bajtova i rasporedima sekcija**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Za Delphi kompajlirane binarne fajlove možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako morate da radite reverse engineering Delphi binarnog fajla, predlažem da koristite IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pritisnite **Alt+F7** u IDA-i da učitate Python plugin, a zatim izaberite fajl plugina.

Ovaj plugin će izvršiti binarni fajl i dinamički razrešiti nazive funkcija na početku debugging-a. Nakon što pokrenete debugging, ponovo pritisnite dugme Start (zeleno dugme ili f9) i breakpoint će se aktivirati na početku pravog koda.

Ako pritisnete dugme u grafičkoj aplikaciji, debugger može da se zaustavi u funkciji koju je to dugme pozvalo.

## Golang

Za uobičajene Go binarne fajlove, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) može da pronađe runtime strukture i poboljša nazive funkcija u IDA-i. Učitajte njegov Python plugin pomoću **Alt+F7**.

Ako morate da radite reverse engineering Golang binarnog fajla, predlažem da koristite IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pritisnite **Alt+F7** u IDA-i da učitate Python plugin, a zatim izaberite fajl plugina.

Ovo će razrešiti nazive funkcija.

### Pronalaženje metapodataka bez tabele simbola

I dalje su potrebni runtime metapodaci da bi stripped Go izvršni fajl mapirao programske brojače na funkcije. [GoReSym](https://github.com/mandiant/GoReSym) pronalazi i parsira strukture kao što su `pclntab` i `moduledata`, koristeći kod izveden iz Go runtime-a. Time se mogu pronaći granice funkcija, nazivi, putanje do izvornog koda, tipovi i detalji o build-u, bez oslanjanja na konvencionalnu tabelu simbola.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator može da ostavi te strukture upotrebljivim, a da pritom zameni oporavljena imena. Garble, na primer, hešira identifikatore i putanje paketa i uklanja informacije o build-u, modulima i debug-u.<sup>[[12]](#references)</sup> Token obfuskovanog paketa mora da ostane dosledan u funkcijama iz tog paketa. Grupisati funkcije prema tokenu koji se ponavlja, zaključiti kom paketu pripadaju na osnovu njihovih pozivaoca, stringova i API-ja, a zatim tu oznaku paketa preneti na celu grupu.<sup>[[13]](#references)</sup>

### Oporavak Garble imena pomoću GoResolver-a

[GoResolver](https://github.com/volexity/GoResolver) kombinuje izdvajanje runtime simbola sa generisanjem čistih referenci i uparivanjem grafova toka kontrole (CFG). Koristite sledeći postupak:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifikujte verziju kompajlera.** Prvo proverite `BuildInfo` i ugrađene stringove verzije. Ako ih je obfuscator uklonio, uporedite delove ugrađenog Go runtime-a sa referentnim runtime-ovima za određene verzije. U testovima kompanije Volexity, oko `2%` runtime-a bilo je dovoljno za razlikovanje glavnih verzija Go-a. Smatrajte ovo empirijskom optimizacijom, a ne univerzalnim pragom.<sup>[[13]](#references)</sup>
2. **Pripremite odgovarajuće reference.** Generišite čiste binarne datoteke za identifikovanu verziju Go-a, ciljnu arhitekturu i verovatne biblioteke. Usklađivanje toolchain-a smanjuje razlike u CFG-u koje generiše kompajler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Uporedite funkcije.** GoGrapher uparuje CFG-ove funkcija i daje normalizovane ocene od `0.0` do `1.0`. Uparivanje osnovnih blokova zasniva se na ponderisanom poređenju sličnih instrukcija. Uparivanja sa visokim stepenom pouzdanosti povezuju randomizovane funkcije sa čistom implementacijom. Slabija uparivanja i dalje mogu da identifikuju paket ili modul.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Proverite i uvezite.** Potvrdite predložena imena pomoću odnosa poziva, konstanti, stringova i sporednih efekata, a zatim uvezite JSON izveštaj pomoću GoResolver plugina za IDA ili Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instalirajte toolchain i pokrenite kombinovani extractor i uparivač grafova:<sup>[[10]](#references)</sup>

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

Podrazumevani prag značajnog poklapanja je `0.9`. Opcije `--extract` i `--graph` mogu da izdvoje bilo koju fazu, dok podrazumevano program pokreće obe, jer se oporavljeni runtime metapodaci i dokazi iz CFG-a međusobno dopunjuju.<sup>[[10]](#references)</sup> CFG ocene su heurističke: inlining, build zastavice, arhitektura i razlike u verzijama biblioteka mogu da promene oblik grafa, zato zadržite nerazrešene funkcije umesto da im dodeljujete nazive sa niskim stepenom pouzdanosti.<sup>[[13]](#references)</sup>

### Oporavak Go tabele stringova

Go binarni fajlovi smeštaju bajtove stringova iz svih povezanih paketa u jednu neprekinutu tabelu. Stavke se ne završavaju NUL bajtom, a runtime strukture ne otkrivaju početnu adresu ni veličinu tabele. Međutim, kompajler na svim operativnim sistemima i arhitekturama prvo sortira stavke po dužini, a zatim abecedno. Zato analitičar može, nakon što pronađe jednu stavku, da pretražuje susedne stavke i koristi unakrsne reference podataka kako bi povezao stringove sa kodom.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatizuje ovaj postupak u IDA Pro i Ghidra. Najpre sačekajte da se završi automatska analiza, jer dodatak zavisi od unakrsnih referenci u segmentu podataka. Podrazumevano koristi runtime string `entersyscall` kao sidro, a zatim može da pretražuje u oba smera, definiše oporavljene stringove u bazi podataka i izveze JSON mapiranje stringova na funkcije koje ih referenciraju.<sup>[[14]](#references)</sup>

Filtrirajte izveštaj prema paketu funkcije koja upućuje na string da biste odvojili kod aplikacije ili malware-a od šuma povezanih biblioteka. Ova tehnika ne može da oporavi literale uništene obfuskacijom, kao što je Garble-ova transformacija `-literals`. I dalje može da organizuje runtime stringove koji su ostali neobfuskirani.<sup>[[14]](#references)[[15]](#references)</sup>

### Oporavak Go runtime tipova

Go ugrađuje informacije o runtime tipovima koje koriste funkcije kao što je garbage collection. Kada su build informacije uklonjene ili disassembler ne parsira ove metapodatke, može da izgleda kao da instrukcije učitavaju proizvoljne adrese podataka, a ciljna oblast ostaje bez tipa. Oporavak metapodataka pretvara te adrese u čitljive reference na tipove i olakšava razumevanje mogućnosti paketa.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) može da izdvoji simbole i parsira runtime tipove u JSON izveštaj. Trenutni CLI koristi podkomandu `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Opcija `-y`/`--types` omogućava parsiranje tipova. Uvezite izveštaj pomoću GoResolver-ovog dodatka za IDA Pro ili Ghidra da biste definisali oporavljene tipove i primenili njihove reference u bazi podataka za analizu. U formatu izveštaja uvedenom ovom funkcijom, ako izostavite `-y`, članovi RTTI address i recovered-types ostaju null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver podržava PE, ELF i Mach-O uzorke za x86, AMD64, ARM i ARM64, pa isti postupak važi za Go binarne datoteke iz Windowsa, Linuxa i macOS-a.<sup>[[10]](#references)</sup>

## Kompajlirani Python

Na ovoj stranici možete pronaći kako da dobijete Python kod iz kompajlirane Python binarne datoteke ELF/EXE formata:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ako dobijete **binarnu datoteku** igre za GBA, možete koristiti različite alate da biste je **emulirali** i **otklanjali greške**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite verziju za otklanjanje grešaka_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

U programu [**no$gba**](https://problemkaputt.de/gba.htm), u odeljku _**Options --> Emulation Setup --> Controls**_** ** možete videti kako se pritiskaju dugmad na Game Boy Advance uređaju

![Konfiguracija kontrola za no$gba koja prikazuje mapiranje dugmadi Game Boy Advance uređaja](<../../images/image (581).png>)

Svaki **taster ima vrednost** koja ga identifikuje kada se pritisne:

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

Dakle, kod ove vrste programa zanimljivo je **kako program obrađuje korisnički unos**. Na adresi **0x4000130** pronaći ćete često prisutnu funkciju: **KEYINPUT**.

![Ghidra prikaz GBA binarne datoteke koja upućuje na KEYINPUT na adresi 0x4000130](<../../images/image (447).png>)

Na prethodnoj slici možete videti da se funkcija poziva iz **FUN_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekih inicijalizacijskih operacija (koje nisu važne):

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

Poslednji if proverava da li je **`uVar4`** među prethodnim tasterima i da nije trenutni taster; to se naziva i otpuštanjem dugmeta (trenutni taster se čuva u **`uVar1`**).

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

- Prvo se upoređuje sa **vrednošću 4** (dugme **SELECT**): u izazovu ovo dugme briše ekran
- Zatim se vrednost upoređuje sa **8** (dugme **START**); u ovom izazovu ta grana proverava da li je uneti kod ispravan.
  - U tom slučaju se promenljiva **`DAT_030000d8`** upoređuje sa 0xf3 i, ako su vrednosti jednake, izvršava se određeni kod.
- U svim ostalim slučajevima proverava se i uvećava brojač (`DAT_030000d4`).\
  Dok je brojač manji od 8, vrednosti pritisnutih tastera sabiraju se u `DAT_030000d8`.

Dakle, u ovom izazovu, znajući vrednosti dugmadi, trebalo je da **pritisnete kombinaciju kraću od 8 tastera čiji je zbir 0xf3.**

**Referenca za ovaj tutorijal:** [arhivirani opis Nostalgia izazova](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [6] [Nostalgia - GBA reversing tutorijal (arhiviran)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Kako savladati AI-potpomognuti reverse engineering ili bar pokušati](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Pristup poređenju grafova toka kontrole zasnovan na uparivanju osnovnih blokova](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repozitorijum](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mehanizam obfuskacije Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: korišćenje sličnosti grafova toka kontrole za automatsku deobfuskaciju Golang binarnih datoteka](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repozitorijum](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: ažuriranja Volexity Golang alata](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: obrnuti inženjering svega](https://github.com/morluto/rea)
- [17] [REA analiza upravljanog koda](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA vodič za CLI i dokaze](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: postupak uklanjanja spljoštavanja toka kontrole u Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF upad putem zero-day ranjivosti, Java loader, web shell i AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README za IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementacija IDA bridge servera](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementacija Ghidra bridge servera](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) se vezuje za adresu wildcard](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Godot alat za reverse engineering](https://github.com/figurophobia/gore)
- [26] [gore implementacija oporavka ključa](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [gore format šifrovanog blob-a](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [gore implementacija komandi i oporavka](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
