# Alati za reverzni inženjering i osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## Alati za reverzni inženjering zasnovani na ImGui

Softver:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automatizacija WinDbg-a u korisničkom režimu

{{#ref}}
windbg-automation.md
{{#endref}}

## Analiza makroa u Office dokumentima

Kod sumnjivih Office dokumenata pregledajte [VBA makro junk code i skrivene UserForm kontrole](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

## Kontrolni tok u Windows-u zasnovan na izuzecima

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Otklanjanje grešaka u Windows kernelu

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm dekompajler / Wat kompajler

Onlajn:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) za **dekompajliranje** iz wasm (binarno) u wat (čitljiv tekst)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) za **kompajliranje** iz wat u wasm
- Možete isprobati i [web-wasmdec](https://wwwg.github.io/web-wasmdec/) za dekompajliranje.

Softver:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 keširani bajtkod

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtuelizovani payload-i i prilagođene VM-ove

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET dekompajler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je dekompajler koji **dekompajlira i pregleda više formata**, uključujući **biblioteke** (.dll), **datoteke Windows metapodataka** (.winmd) i **izvršne datoteke** (.exe). Nakon dekompajliranja, sklop se može sačuvati kao Visual Studio projekat (.csproj).

Prednost je u tome što ova radnja može uštedeti vreme ako je potrebno obnoviti izgubljeni izvorni kod iz zastarelog sklopa. Pored toga, dotPeek omogućava praktičnu navigaciju kroz dekompajlirani kod, što ga čini jednim od idealnih alata za **analizu Xamarin algoritama.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Uz sveobuhvatan model dodataka i API koji omogućava prilagođavanje alata vašim potrebama, .NET Reflector štedi vreme i pojednostavljuje razvoj. Pogledajmo mnoštvo usluga reverznog inženjeringa koje ovaj alat pruža:

- Omogućava uvid u tok podataka kroz biblioteku ili komponentu
- Pruža uvid u implementaciju i upotrebu .NET jezika i okvira
- Pronalaženje nedokumentovanih i neizloženih funkcionalnosti omogućava bolje iskorišćavanje API-ja i korišćenih tehnologija.
- Pronalaženje zavisnosti i različitih sklopova
- Pronalazi tačno mesto grešaka u vašem kodu, komponentama trećih strana i bibliotekama.
- Otklanja greške u izvornom kodu svih .NET programa sa kojima radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy dodatak za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga instalirati direktno iz VSCode-a, bez preuzimanja sa git-a. Kliknite na **Extensions** i **potražite ILSpy**).\
Ako treba da **dekompajlirate**, **izmenite** i ponovo **kompajlirate**, možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegov aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Desni klik -> Modify Method** da biste nešto promenili unutar funkcije).

### Pregled upravljanog koda bez izvršavanja pomoću REA

**REA** može da pregleda PE/CLI metapodatke i CIL bez učitavanja sklopa. Počnite od identiteta artefakta, a zatim pregledajte članove i deklarisane nativne granice; ovo je korisno prilikom analize sumnjivih poziva pre upotrebe dekompajlera ili pokretanja programa.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Za poređenje verzija, `compare_managed_members` koristi sirovi identitet CIL-a/potpisa i otiske dekodiranih instrukcija, umesto da tretira metapodatkovne tokene kao stabilne između buildova. Deklaracija P/Invoke nije dokaz da je native kod pokrenut; `verify_managed_native_boundaries` zahteva odgovarajući native export ili dokaz o funkciji da bi proverio tu granicu. Sačuvajte digest artefakta, MVID i nerazrešena mapiranja uz rezultat.<sup>[[17]](#references)</sup>

### DNSpy Logging

Da bi DNSpy beležio neke informacije u datoteku, možete da upotrebite ovaj isečak koda:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Da biste otklanjali greške u kodu pomoću DNSpy-a, potrebno je da:

Najpre promenite **Assembly attributes** koji se odnose na **debugging**:

![DNSpy Logging - DNSpy Debugging: Najpre promenite Assembly attributes koji se odnose na debugging](<../../images/image (973).png>)

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

Ovo je neophodno jer će se u suprotnom tokom **izvršavanja** primeniti nekoliko **optimizacija** na kod, pa je moguće da se **tačka prekida nikada ne aktivira** tokom debagovanja ili da neke **promenljive ne postoje**.

Zatim, ako vašu .NET aplikaciju pokreće **IIS**, možete je **ponovo pokrenuti** pomoću:

```
iisreset /noforce
```

Zatim, da biste počeli sa debuggingom, zatvorite sve otvorene datoteke i u kartici **Debug** izaberite **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste počeli sa debuggingom, zatvorite sve otvorene datoteke i u kartici Debug izaberite Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste se povezali sa **IIS serverom** i kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste se povezali sa IIS serverom i kliknite na attach](<../../images/image (113).png>)

Sada kada debugujemo proces, zaustavite ga i učitajte sve module. Prvo kliknite na _Debug >> Break All_, a zatim na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, zaustavite ga i učitajte sve module. Prvo kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, zaustavite ga i učitajte sve module. Prvo kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u odeljku **Modules** i izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u odeljku Modules i izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom miša na bilo koji modul u **Assembly Explorer** i izaberite **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom miša na bilo koji modul u Assembly Explorer i izaberite Sort Assemblies](<../../images/image (339).png>)

## Java dekompajler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugovanje DLL-ova

### Korišćenje IDA-e

- **Učitajte rundll32** (64-bitna verzija se nalazi u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- Izaberite debugger **Windbg**
- Izaberite "**Suspend on library load/unload**"

![Debugovanje DLL-ova - Korišćenje IDA-e: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Podesite **parametre** izvršavanja tako što ćete uneti **putanju do DLL-a** i funkciju koju želite da pozovete:

![Debugovanje DLL-ova - Korišćenje IDA-e: Podesite parametre izvršavanja tako što ćete uneti putanju do DLL-a i funkciju koju želite da pozovete](<../../images/image (704).png>)

Kada pokrenete debugging, **izvršavanje će se zaustaviti pri učitavanju svakog DLL-a**. Dakle, kada rundll32 učita vaš DLL, izvršavanje će se zaustaviti.

Ovaj metod zaustavlja izvršavanje pri događajima učitavanja modula, ali dolazak do entry point-a učitanog DLL-a manje je direktan nego u x64dbg postupku ispod.

### Korišćenje x64dbg/x32dbg

- **Učitajte rundll32** (64-bitna verzija se nalazi u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- **Promenite Command Line** ( _File --> Change Command Line_ ) i unesite putanju do DLL-a i funkciju koju želite da pozovete, na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- U _Options --> Settings_ izaberite "**DLL Entry**".
- Zatim **pokrenite izvršavanje**. Debugger će se zaustaviti pri svakoj funkciji dll main; u nekom trenutku će se **zaustaviti na entry point-u vašeg DLL-a**. Odatle potražite mesta na koja želite da postavite breakpoint.

Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, na **vrhu prozora win64dbg-a** možete videti **u kom se kodu nalazite**:

![Korišćenje IDA-e - Korišćenje x64dbg/x32dbg: Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg-u, na vrhu prozora win64dbg-a možete videti u kom se kodu nalazite](<../../images/image (842).png>)

Ovaj indikator potvrđuje kada se izvršavanje zaustavilo unutar DLL-a koji želite da debugujete.

## GUI aplikacije / video-igre

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje važnih vrednosti sačuvanih u memoriji pokrenute igre i njihovu izmenu. Više informacija:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end alat za reverse engineering za GNU Project Debugger (GDB), fokusiran na igre. Međutim, može se koristiti za bilo šta povezano sa reverse engineeringom.

[**Decompiler Explorer**](https://dogbolt.org/) je web front-end za više dekompajlera. Ova web usluga omogućava poređenje izlaza različitih dekompajlera za male izvršne datoteke.

### Dešifrovanje Godot PCK datoteka i oporavak projekta

Kod distribuirane Godot igre, pronađite njen PCK u zasebnoj `.pck` datoteci, dodatom ili ugrađenom paketu izvršne datoteke ili direktorijumu `assets` APK-a. [gore](https://github.com/figurophobia/gore) može da pregleda i raspakuje paket, dok je za potpunu rekonstrukciju skripti i resursa potreban GDRE Tools (`gore setup` ga instalira, a možete koristiti i `--gdre`). Ovaj alat podržava Godot 4.x PCK formate v2–v4 za ovaj postupak; može da prepozna v1 zaglavlja, ali za v1 je potreban prosleđeni ključ.<sup>[[25]](#references)</sup>

Automatski oporavak ključa zahteva šifrovanu tabelu datoteka; ako je šifrovan samo sadržaj datoteka, navedite poznati ključ. Neuspešan oporavak ne znači da paket nije šifrovan.<sup>[[28]](#references)</sup>

Pretraga ključa **nije napad na prostor ključeva AES-256**. Šifrovana tabela datoteka otkriva MD5 vrednost njenog otvorenog teksta, dužinu otvorenog teksta, IV i AES-256-CFB šifrat.<sup>[[27]](#references)</sup> `gore` proverava prozore od 32 bajta iz izvršne datoteke igre ili obližnjih datoteka kao moguće ključeve. Kandidate filtrira prema verovatnoj dužini i prefiksu dešifrovane putanje, a pogotke pronađene skeniranjem binarnih podataka potvrđuje dešifrovanjem cele tabele i proverom njenog MD5-a.<sup>[[26]](#references)[[28]](#references)</sup> Najpre pretražuje inicijalizovane PE/ELF odeljke sa podacima, a zatim, ako je potrebno, celu datoteku; `--scan` dodaje druge datoteke kandidatkinje.<sup>[[28]](#references)</sup>

Ako ugrađeni ključ nije pronađen, isprobava se mala ugrađena lista lozinki; `--wordlist` prosleđuje druge kandidate. Svaka lozinka se proverava kao zapis ključa izvedenog iz lozinke koji koristi engine, kao vrednost dopunjena nulama ili kao ključ od 64 heksadecimalna znaka. Za razliku od pogodaka pronađenih skeniranjem binarnih podataka, pogoci sa wordlist-a u ovoj implementaciji prolaze samo proveru strukture putanje. Potvrdite ih tako što ćete otvoriti paket i proveriti izdvojene resurse.<sup>[[26]](#references)[[28]](#references)</sup>

Kada je artefakt igre dostupan lokalno, izaberite fazu potrebnu za analizu. `recover` poziva GDRE da rekonstruiše projekat koji može da se otvori, dok `extract` samo raspakuje sirove datoteke. `key` ispisuje mogući ključ za upotrebu sa drugim alatom.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Istraga native koda potkrepljena dokazima uz REA

**REA** omogućava analizu u Hopperu, Ghidri i IDA-i putem CLI-ja i MCP-a. Zahteva Node.js 22.x (najmanje 22.19), 24.x (najmanje 24.11) ili 26+, kao i npm. Najpre konfigurišite postojećeg native provajdera; proverite `rea providers --json` i izričito izaberite provajdera ako ih više podržava cilj. Umesto `0x1000` ispod upotrebite ime ili adresu funkcije zabeleženu u inventaru.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Počnite od stringa ili simbola funkcije, pratite reference i pozivače, a zatim pregledajte dosije izabrane funkcije i pseudokod pomoću `rea decompile`. REA vezuje sesiju za izabranog provajdera, umesto da ga neprimetno zameni nakon greške. Za ponovljive upite, `--snapshot PATH` ponovo koristi samo bajtove artefakta, provajdera, podešavanja, operaciju i parametre koji se podudaraju; snapshot je lokalna keš memorija, a ne sačuvana baza podataka provajdera. Sačuvajte vraćene Evidence i eksplicitne nepoznanice, umesto da izvedene putanje ili tekst dekompilatora tretirate kao izvorni kod.<sup>[[16]](#references)[[18]](#references)</sup>

Za JavaScript/Electron ulazne tačke koje vode do nativnih dodataka pogledajte [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Skriptovana analiza IDA i Ghidra pomoću lokalnog TCP mosta

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) radi unutar **već otvorene** IDA baze podataka ili Ghidra CodeBrowser programa i omogućava zasebnoj skripti da šalje upite analitičkoj bazi podataka i menja je. Pokrenite `ID_Server.py` iz IDA Python CLI-ja (`import ID_Server`) ili `Ghidra_Server.py` iz Ghidra Script Manager-a. IDA se vezuje za `127.0.0.1`, počevši od porta `5073`, i proverava više portove. Trenutna Ghidra skripta počinje od porta `5093` i pokušava deset portova do `5102`; njen Java socket se vezuje za wildcard adresu, a ne samo za loopback. Pre povezivanja proverite port koji je ispisala instanca. Za razliku od headless analizatora, ovaj most radi nad programom koji je trenutno otvoren u toj GUI instanci.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Pošaljite **jednu komandu završenu znakom za novi red po konekciji** i pročitajte odgovor završen znakom za novi red. Rezultat je obično JSON. Na primer, nakon pronalaženja uvezene API funkcije relevantne za ulaznu putanju, `IMPORTXREF` pronalazi njena mesta pozivanja; zatim `DECOMP_XREF` grupno dekompajlira pozivače izabrane adrese. `FUNC` pregledava funkciju, dok `PCODE` vraća međureprezentaciju dekompilatora. Koristite adresu iz aktivne baze podataka, a ne adresu kopiranu iz binarne datoteke sa drugačijom baznom adresom. Primer ispod koristi IDA podrazumevani port; za Ghidra koristite port koji je ispisala njena skripta.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Isti kanal može da **menja bazu podataka za analizu**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` i `PATCH` menjaju nazive, tipove, definicije struktura, granice funkcija ili sačuvane bajtove. `PATCH` je izmena baze podataka, **a ne** dokaz da je izvršen patch u živom procesu. Nijedan listener ne dokumentuje autentifikaciju. IDA je dostupan samo preko loopback-a, ali Ghidra može biti dostupan preko mrežnih interfejsa; ograničite pristup Ghidra listener-u kada ga koristite. `QUIT` zaustavlja bilo koji listener, a IDA izlaže i `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugovanje shellcode-a pomoću blobrunner-a

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alocira **shellcode**, ispisuje njegovu **memorijsku adresu** i pauzira izvršavanje.\
Prikačite debugger kao što je IDA ili x64dbg, postavite breakpoint na ispisanu adresu i nastavite izvršavanje da biste debugovali shellcode.

Na GitHub stranici izdanja nalaze se zip arhive sa kompajliranim izdanjima: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Nešto izmenjenu verziju Blobrunner-a možete pronaći na sledećem linku. Da biste je kompajlirali, samo **napravite C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod, pa ga izgradite**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugovanje shellcode-a pomoću jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je sličan BlobRunner-u. Alocira shellcode i ulazi u beskonačnu petlju. Prikačite debugger, nastavite izvršavanje na **2–5 sekundi**, pauzirajte unutar te petlje i korak-po-korak dođite do sledećeg poziva koji prenosi izvršavanje na alocirani shellcode.

![Debugger pauziran u beskonačnoj petlji jmp2it-a, neposredno pre poziva koji prenosi izvršavanje na alocirani shellcode](<../../images/image (509).png>)

Kompajliranu verziju [jmp2it-a možete preuzeti sa stranice izdanja](https://github.com/adamkramer/jmp2it/releases/).

### Debugovanje shellcode-a pomoću Cutter-a

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI za radare. Pomoću Cutter-a možete emulirati shellcode i dinamički ga analizirati.

Imajte u vidu da Cutter omogućava opcije „Open File“ i „Open Shellcode“. U mom slučaju, kada sam shellcode otvorio kao datoteku, ispravno ga je dekompilirao, ali kada sam ga otvorio kao shellcode, nije:

![Cutter prikazuje različite rezultate analize pri otvaranju istih bajtova kao datoteke i kao shellcode-a](<../../images/image (562).png>)

Da biste pokrenuli emulaciju na željenom mestu, postavite bp na to mesto; izgleda da će Cutter automatski pokrenuti emulaciju odatle:

![Postavljanje breakpoint-a na željeni ulaz shellcode-a pre pokretanja Cutter emulacije](<../../images/image (589).png>)

![Cutter emulator pauziran na izabranom breakpoint-u shellcode-a](<../../images/image (387).png>)

Na primer, stack možete videti u hex dump-u:

![Prikaz stack-a emuliranog shellcode-a u Cutter-ovom hex dump-u](<../../images/image (186).png>)

### Deobfuskacija shellcode-a i pronalaženje izvršenih funkcija

Probajte [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Prikazaće vam, između ostalog, **koje funkcije** shellcode koristi i da li se shellcode **dekodira** u memoriji.

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

Opcija **Create Dump** će napraviti dump konačnog shellcode-a ako se on dinamički izmeni u memoriji (korisno za preuzimanje dekodiranog shellcode-a). **start offset** može biti koristan za pokretanje shellcode-a od određenog pomeraja. Opcija **Debug Shell** korisna je za otklanjanje grešaka u shellcode-u pomoću terminala scDbg-a (ipak, za ovo smatram da je bilo koja od ranije objašnjenih opcija bolja, jer ćete moći da koristite Ida ili x64dbg).

### Disasembliranje pomoću CyberChef-a

Otpremite datoteku shellcode-a kao ulaz i upotrebite sledeći recept da biste ga dekompilirali: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Uklanjanje MBA obfuskacije

Obfuskacija **Mixed Boolean-Arithmetic (MBA)** sakriva jednostavne izraze poput `x + y` iza formula koje kombinuju aritmetičke (`+`, `-`, `*`) i bitovne operatore (`&`, `|`, `^`, `~`, pomeranja). Važno je da su ovi identiteti obično tačni samo u okviru **modularne aritmetike fiksne širine**, pa su prenosi i prekoračenja bitni:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ako pojednostavite ovaj izraz pomoću generičkih alata za algebru, lako možete dobiti pogrešan rezultat jer semantika širine bita nije uzeta u obzir.<sup>[[1]](#references)</sup>

### Praktični tok rada

1. **Sačuvajte originalnu širinu bita** iz podignutog koda/IR-a/izlaza dekompilatora (`8/16/32/64` bita).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
   - **Linearan**: ponderisani zbirovi bitovskih atoma
   - **Semilinearan**: linearni izraz sa konstantnim maskama kao što je `x & 0xFF`
   - **Polinomski**: prisutni su proizvodi
   - **Mešovit**: proizvodi i bitovska logika su isprepletani, često uz ponovljene podizraze
3. **Proverite svaku moguću transformaciju** nasumičnim testiranjem ili SMT dokazom. Ako se ekvivalencija ne može dokazati, zadržite originalni izraz umesto da nagađate.

### Zaobiđite spljošteni kontrolni tok pomoću uskog isečka izvršavanja

Oporavak kompletnog grafa kontrolnog toka često nije potreban. Kod flattening-a kontrolnog toka, neprozirnih predikata, velikih dispatcher-a ili koda sa mnogo MBA izraza, pratite reference od šifrovanih blokova podataka i izlaznih bafera do najmanje rutine koja ih transformiše. Zatim reprodukujte samo taj isečak toka podataka ili ga izvršite nezavisno; dispatcher nije deo potrebnog rešenja ako se relevantno stanje može direktno inicijalizovati.<sup>[[7]](#references)</sup>

Praktični tok rada je:<sup>[[7]](#references)</sup>

1. Napravite popis izvršnih odeljaka i odeljaka sa podacima, relokacija i unakrsnih referenci. Izdvojite moguće tabele iz `.rodata`, uz očuvanje redosleda bajtova i širine elemenata.
2. Identifikujte poslednju rutinu koja upisuje otvoreni tekst ili izlazni bafer. Zabeležite njene ulaze, referencirane tabele, uvezene pozive i potrebno globalno stanje.
3. Podignite samo te operacije u Python model fiksne širine. Ako isečak i dalje zavisi od previše stanja, pozovite rutinu pomoću alata Unicorn, QEMU ili debugger-a i zakačite nebitne uvezene funkcije umesto da emulirate ceo program.
4. Proverite da li extractor zaista izvodi izlaz iz dostavljenog binarnog fajla: uklonite tihe rezervne opcije, pretražite ga u potrazi za ugrađenim odgovorima i pokрените га на невиђеним верзијама са измењеним стринговима, кључевима, идентификаторима, распоредом података и seed-овима за обфускацију.

Korisne komande za prvi prolaz su:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Otkrivanje MBA izraza koji prikrivaju konstante

Izraz nad bajtom koji naizgled zavisi od ulaza može u potpunosti da poništi svoj ulaz. Nakon izdvajanja tabela, evaluirajte izraz nad celim 8-bitnim domenom; skup izlaznih vrednosti koji sadrži samo jednu vrednost dokazuje da je taj bajt konstanta, bez potrebe za rekonstrukcijom okolne mašine stanja.<sup>[[7]](#references)</sup>

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

Zadržite završnu masku jer se pri originalnom sabiranju vrednost prelama na širinu bajta. Za širi domen, pitajte SMT solver da li je za dva simbolička ulaza iste širine zadovoljivo `f(x1) != f(x2)`: `unsat` dokazuje invarijantnost, dok `sat` daje kontraprimer i znači da se ulaz ne može odbaciti.<sup>[[7]](#references)</sup>

#### Prepoznajte dekodiranje vezano za okruženje

Provere protiv analize ne moraju da granaju izvršavanje niti da izazovu pad. Dekoder može da ugradi rezultat senzora u bit ključa, konstantu opaque-predicate-a ili stanje spljoštenog dispečera, da nastavi normalno i da u emulatoru proizvede uverljiv, ali netačan čist tekst. Zato nije dovoljno zakrpiti samo vidljive grane za slučaj greške; pratite zavisnosti podataka od provera okruženja do stanja dekodera, uporedite isti isečak na autentičnom uređaju i u emulatoru i proverite kako forsiranje rezultata svakog senzora menja završni bafer.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktičan MBA pojednostavljivač za analizu malware-a i reverzni inženjering zaštićenih binarnih datoteka. Klasifikuje izraz i usmerava ga kroz specijalizovane pipeline-ove, umesto da na sve primenjuje jedan generički prolaz za prepisivanje.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evaluira izraz na Boolean ulazima, izvodi potpis i paralelno isprobava nekoliko metoda oporavka, kao što su pattern matching, ANF konverzija i interpolacija koeficijenata.
- **Semilinear MBA**: Atomi maskirani konstantama rekonstruišu se pomoću rekonstrukcije particionisane po bitovima, tako da maskirani regioni ostanu ispravni.
- **Polynomial/Mixed MBA**: Proizvodi se dekomponuju na jezgra, a ponovljeni podizrazi mogu da se izdvoje u privremene promenljive pre pojednostavljivanja spoljne relacije.

Primer mešovitog identiteta koji često vredi pokušati rekonstruisati:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Ovo se može svesti na:

```c
x * y
```

### Napomene o reverziranju

- Prednost dajte pokretanju CoBRA nad **lifted IR izrazima** ili izlazom dekompilatora, nakon što izdvojite tačan proračun.
- Eksplicitno koristite `--bitwidth` kada izraz potiče od maskirane aritmetike ili registara uske širine.
- Ako vam je potreban stroži korak dokazivanja, pogledajte lokalne Z3 beleške ovde:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA se isporučuje i kao **LLVM pass plugin** (`libCobraPass.so`), što je korisno kada želite da normalizujete LLVM IR sa mnogo MBA izraza pre kasnijih faza analize.
- Nepodržane mešovite reziduale domena osetljive na prenos treba smatrati signalom da zadržite originalni izraz i ručno analizirate put prenosa.

## Oporavak XOR-state control-flow flattening-a

OLLVM-style flattener može da čuva trenutno stanje basic block-a u dva 64-bitna registra i da ga rekonstruiše pomoću XOR-a u dispatcher-u. Svaki originalni blok upisuje par za svoje sledeće stanje i skače nazad u dispatcher. Uslovni blok može da koristi `CMOVcc` za zamenu jedne polovine para na osnovu CPU flagova, pa praćenje samo vidljivih branch instrukcija propušta dva moguća naslednika. Za razliku od dispatcher-a sa indirektnim skokom, ovaj oblik može svuda da koristi direktne povratne skokove.<sup>[[19]](#references)[[20]](#references)</sup>

Da biste rekonstruisali graf, identifikujte stablo poređenja dispatcher-a i dva registra stanja, mapirajte svako poređeno XOR stanje na ciljni blok, a zatim pratite upise u par registara koji se javljaju u svakom originalnom bloku. Za uslovne upise uključite instrukciju koja postavlja flagove i oba ishoda `CMOVcc`. Prepišite izlaz svakog bloka ka dispatcher-u u njegov razrešeni direktni naslednik ili uslovni branch; dispatcher tada postaje nedostižan, bez izmena binarnog fajla. Ovo je pristup koji obuhvata ceo CFG; ako je važan samo jedan decoder, možda će brže ići [workflow za uski execution slice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) iznad.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatizuje ovaj oblik u Binary Ninja. Kopirajte `plugins/DispatchThis` u direktorijum korisničkih plugin-ova za Binary Ninja i restartujte program. U pogođenoj funkciji otvorite **Function Settings** i izaberite `OLLVM_XOR_64`; ako analiza ne počne, izaberite **Analysis → Reanalyze All Functions**. Ovaj režim prepisuje MLIL kontrolne ivice, a ne bajtove fajla, i ne zahteva Z3 ni resolver indirektnih skokova. Testiran je na Binary Ninja 5.3.9757+; ne uklanja neaktivne upise stanja po blokovima, zato ih nemojte pomešati sa preostalim aktivnim tranzicijama.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuscator zamenjuje operacije programa nizovima instrukcija zasnovanim na `mov` i koristi obradu signala/izuzetaka za izmenu toka kontrole. Detalji:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Za podržane binarne fajlove, [demovfuscator](https://github.com/kirschju/demovfuscator) može da deobfuskuje rezultat. Ima nekoliko zavisnosti.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

I [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako igrate **CTF, ovaj način za pronalaženje flag-a** može biti veoma koristan: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **ulaznu tačku**, pretražite funkcije po `::main`, kao u primeru:

![Pronalaženje Rust ulazne tačke u Ghidri pretragom naziva funkcija za dvotačku dvotačku main](<../../images/image (1080).png>)

U ovom slučaju, binarna datoteka se zvala authenticator, pa je prilično očigledno da je ovo zanimljiva main funkcija.\
Ako znate **nazive** pozivanih **funkcija**, potražite ih na **Internetu** da biste saznali više o njihovim **ulazima** i **izlazima**.

### Oporavak Rust stringova iz ELF firmvera

U **Rust ELF** binarnim datotekama, mnogi statički stringovi nisu referencirani pokazivačima sa NUL završetkom u C stilu. Uobičajen `rustc` raspored je **torka pokazivača i dužine** unutar **`.data.rel.ro`**, koja pokazuje na stvarni blok stringova smešten u **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

To znači da `strings` ili podrazumevana analiza u Ghidri mogu spojiti susedne stringove ili potpuno propustiti unakrsne reference.<sup>[[3]](#references)</sup>

Brzi postupak:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Preuzmite virtuelnu adresu i veličinu odeljka **`.rodata`**.
2. Nabrojte sadržaj odeljka **`.data.rel.ro`** reč po reč.
3. Svaku vrednost unutar opsega adresa odeljka `.rodata` tretirajte kao kandidata za pokazivač na string.
4. Sledeću reč tretirajte kao kandidata za dužinu.
5. Primienite provere ispravnosti (na primer, zadržite dužine između **4** i **100** bajtova).
6. Pročitajte tačno `length` bajtova iz odeljka `.rodata`, umesto da pretražujete dok ne naiđete na `0x00`.

Minimalna logika ekstraktora:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

This is posebno korisno pri firmware reversing-u jer oporavljeni Rust stringovi često otkrivaju **HTTP rute, RPC nazive, log poruke, assertion-e, nazive datoteka, config ključeve, command handler-e i logiku povezanu sa autentifikacijom**.

Ako Ghidra ne pronađe te stringove, pokrenite custom script/plugin koji primenjuje istu heuristiku i kreira string data na referenciranim `.rodata` offset-ima. Objavljeni alati `rust-strings` i `RustStrings.py` kompanije Pen Test Partners dobri su primeri za prilagođavanje ove ideje drugim **veličinama reči, redosledima bajtova i rasporedima sekcija**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Za binarne datoteke kompajlirane za Delphi možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako treba da radite reverse Delphi binarne datoteke, predlažem da koristite IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pritisnite **Alt+F7** u IDA-i da učitate Python plugin, pa izaberite datoteku plugina.

Ovaj plugin će izvršiti binarnu datoteku i dinamički razrešiti nazive funkcija na početku debugging-a. Nakon pokretanja debugging-a, ponovo pritisnite dugme Start (zeleno dugme ili f9) i breakpoint će se aktivirati na početku pravog koda.

Ako pritisnete dugme u grafičkoj aplikaciji, debugger može da se zaustavi u funkciji koju to dugme poziva.

## Golang

Za obične Go binarne datoteke, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) može da oporavi runtime strukture i poboljša nazive funkcija u IDA-i. Učitajte njegov Python plugin pomoću **Alt+F7**.

Ako treba da radite reverse Golang binarne datoteke, predlažem da koristite IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pritisnite **Alt+F7** u IDA-i da učitate Python plugin, pa izaberite datoteku plugina.

Ovo će razrešiti nazive funkcija.

### Oporavak metapodataka bez tabele simbola

Ogoljena Go izvršna datoteka i dalje zahteva runtime metapodatke za mapiranje programskih brojača na funkcije. [GoReSym](https://github.com/mandiant/GoReSym) pronalazi i parsira strukture kao što su `pclntab` i `moduledata`, koristeći kod izveden iz Go runtime-a. Ovo može da oporavi granice funkcija, nazive, izvorne putanje, tipove i detalje o build-u bez oslanjanja na konvencionalnu tabelu simbola.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator može da ostavi te strukture upotrebljivim, a da zameni pronađena imena. Garble, na primer, hešira identifikatore i putanje paketa i uklanja informacije o build-u, modulima i debagovanju.<sup>[[12]](#references)</sup> Token obfuskovanog paketa mora da ostane dosledan u svim funkcijama iz tog paketa. Grupisati funkcije prema tokenu koji se ponavlja, zaključiti koji je paket na osnovu njegovih pozivaoca, stringova i API-ja, pa zatim dodeliti oznaku tog paketa celoj grupi.<sup>[[13]](#references)</sup>

### Oporavak Garble imena pomoću GoResolver-a

[GoResolver](https://github.com/volexity/GoResolver) kombinuje izdvajanje runtime simbola sa generisanjem čistih referenci i uparivanjem grafa toka kontrole (CFG). Koristite sledeći redosled:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifikujte verziju kompajlera.** Prvo isprobajte `BuildInfo` i ugrađene stringove verzije. Ako ih je obfuscator uklonio, uporedite delove priloženog Go runtime-a sa runtime-ovima za referentne verzije. U Volexity testovima, oko `2%` runtime-a bilo je dovoljno za razlikovanje glavnih verzija Go-a. Tretirajte ovo kao empirijsku optimizaciju, a ne kao univerzalni prag.<sup>[[13]](#references)</sup>
2. **Pripremite odgovarajuće reference.** Generišite čiste binarne datoteke za identifikovanu verziju Go-a, ciljnu arhitekturu i verovatne biblioteke. Usklađivanje toolchain-a smanjuje razlike u CFG-u koje generiše kompajler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Uporedite funkcije.** GoGrapher uparuje CFG-ove funkcija i daje normalizovane ocene od `0.0` do `1.0`. Uparivanje osnovnih blokova zasniva se na ponderisanom poređenju sličnih instrukcija. Uparivanja sa visokim stepenom pouzdanosti mapiraju randomizovane funkcije na čistu implementaciju. Slabija uparivanja i dalje mogu da identifikuju paket ili modul.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Proverite i uvezite.** Potvrdite predložena imena pomoću odnosa poziva, konstanti, stringova i sporednih efekata, a zatim uvezite JSON izveštaj pomoću GoResolver plugina za IDA ili Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instalirajte toolchain i pokrenite kombinovani extractor i matcher grafova:<sup>[[10]](#references)</sup>

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

Podrazumevani prag za značajno poklapanje je `0.9`. Prekidači `--extract` i `--graph` mogu da izdvoje bilo koju od faza, dok se podrazumevano pokreću obe jer se oporavljeni runtime metapodaci i dokazi iz CFG-a međusobno dopunjuju.<sup>[[10]](#references)</sup> CFG ocene su heurističke: inlining, build flags, arhitektura i razlike u verzijama biblioteka mogu da promene oblik grafa, zato zadržite nerešene funkcije umesto da im dodeljujete imena sa niskim nivoom pouzdanosti.<sup>[[13]](#references)</sup>

### Oporavak Go tabele stringova

Go binarne datoteke smeštaju bajtove stringova iz svih povezanih paketa u jednu neprekidnu tabelu. Unosi se ne završavaju nulom, a runtime strukture ne izlažu početnu adresu ni veličinu tabele. Međutim, kompajler raspoređuje unose prvo po dužini, a zatim abecedno, na svim operativnim sistemima i arhitekturama. Zato analitičar, nakon što pronađe jedan unos, može da prolazi kroz susedne unose i koristi unakrsne reference podataka kako bi povezao stringove sa kodom.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatizuje ovaj postupak u IDA Pro i Ghidra. Najpre sačekajte da se završi automatska analiza jer dodatak koristi unakrsne reference segmenata podataka. Podrazumevana sidrena vrednost je runtime string `entersyscall`; nakon toga dodatak može da pretražuje u oba smera, definiše oporavljene stringove u bazi podataka i izveze JSON mapiranje stringova na funkcije koje ih referenciraju.<sup>[[14]](#references)</sup>

Filtrirajte izveštaj prema paketu funkcije koja referencira string da biste razdvojili kod aplikacije ili malware-a od šuma povezanih biblioteka. Ova tehnika ne može da oporavi literale uništene obfuskacijom, kao što je Garble-ova transformacija `-literals`. I dalje može da organizuje runtime stringove koji su ostali neobfuskirani.<sup>[[14]](#references)[[15]](#references)</sup>

### Oporavak Go runtime tipova

Go ugrađuje informacije o runtime tipovima koje koriste funkcije kao što je garbage collection. Kada su build informacije uklonjene ili disassembler ne parsira ove metapodatke, može izgledati da instrukcije učitavaju proizvoljne adrese podataka, a ciljna oblast ostaje bez tipa. Oporavak metapodataka pretvara te adrese u čitljive reference na tipove i olakšava razumevanje mogućnosti paketa.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) može da izdvoji simbole i parsira runtime tipove u JSON izveštaj. Trenutni CLI koristi podkomandu `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Opcija `-y`/`--types` omogućava parsiranje tipova. Uvezite izveštaj pomoću GoResolver dodatka za IDA Pro ili Ghidra da biste definisali oporavljene tipove i primenili njihove reference u bazi podataka analize. U formatu izveštaja uvedenom ovom funkcijom, ako izostavite `-y`, članovi za RTTI adresu i oporavljene tipove ostaju null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver podržava PE, ELF i Mach-O uzorke za x86, AMD64, ARM i ARM64, pa se isti postupak može primeniti na Go binarne fajlove iz sistema Windows, Linux i macOS.<sup>[[10]](#references)</sup>

## Kompajlirani Python

Na ovoj stranici možete pronaći uputstva za dobijanje Python koda iz ELF/EXE binarnog fajla kompajliranog iz Pythona:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ako nabavite **binary** GBA igre, možete koristiti različite alate da biste je **emulirali** i **debugovali**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite debug verziju_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra dodatak
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra dodatak

U programu [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_** ** možete videti kako da pritisnete dugmad za Game Boy Advance

![Konfiguracija kontrola no$gba koja prikazuje mapiranje dugmadi za Game Boy Advance](<../../images/image (581).png>)

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

Poslednji if proverava da li se **`uVar4`** nalazi među poslednjim tasterima i da nije trenutni taster, odnosno da li je dugme otpušteno (trenutni taster je sačuvan u **`uVar1`**).

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

U prethodnom kodu možete videti da upoređujemo **uVar1** (mesto gde se nalazi **vrednost pritisnutog dugmeta**) sa nekim vrednostima:

- Prvo se poredi sa **vrednošću 4** (dugme **SELECT**): u ovom izazovu ovo dugme briše ekran
- Zatim se poredi sa **vrednošću 8** (dugme **START**); u ovom izazovu ova grana proverava da li je uneti kod ispravan.
  - U ovom slučaju, var **`DAT_030000d8`** poredi se sa 0xf3, a ako su vrednosti iste, izvršava se određeni kod.
- U svim drugim slučajevima proverava se i uvećava brojač (`DAT_030000d4`).\
  Dok je brojač manji od 8, vrednosti pritisnutih tastera sabiraju se u `DAT_030000d8`.

Dakle, u ovom izazovu, kada znate vrednosti dugmadi, trebalo je da **pritisnete kombinaciju kraću od 8 tastera čiji je zbir 0xf3.**

**Izvor za ovaj vodič:** [arhivirani opis Nostalgia izazova](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursevi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (deobfuskacija binarnih fajlova)

## References

- [1] [Pojednostavljivanje MBA obfuskacije pomoću CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [CoBRA repozitorijum Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Dekodiranje Rust stringova - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - Rust stringovi](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - vodič za GBA reversing (arhivirano)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Kako pobediti AI-potpomognuti reverse engineering, ili bar pokušati](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Pristup poređenju grafova toka kontrole zasnovan na uparivanju osnovnih blokova](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repozitorijum](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mehanizam obfuskacije Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Korišćenje sličnosti grafova toka kontrole za automatsku deobfuskaciju Golang binarnih fajlova](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repozitorijum](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Novosti u Volexity alatima za Golang](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Obrnuti inženjering bilo čega](https://github.com/morluto/rea)
- [17] [Analiza upravljanog koda u REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA vodič za CLI i dokaze](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Tok rada za uklanjanje izravnavanja toka kontrole u Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: Upad putem zero-day ranjivosti PaperCut MF, Java loader, web shell i AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README za IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementacija IDA bridge servera](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementacija Ghidra bridge servera](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) se vezuje za adresu džoker](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: komplet alata za Godot reverse engineering](https://github.com/figurophobia/gore)
- [26] [Implementacija oporavka ključa u gore](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [Format šifrovanog blob-a u gore](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [Implementacija komandi i oporavka u gore](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
