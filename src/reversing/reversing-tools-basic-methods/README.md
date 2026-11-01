# Alati za reversing i osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## Alati za reversing zasnovani na ImGui

Softver:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automatizacija WinDbg-a u korisničkom režimu

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows tok kontrole vođen izuzecima

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Otklanjanje grešaka u Windows kernelu

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm dekompajler / Wat kompajler

Na mreži:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) za **dekompajliranje** iz wasm-a (binarni format) u wat (čitljiv tekst)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) za **kompajliranje** iz wat-a u wasm
- Možete isprobati i [web-wasmdec](https://wwwg.github.io/web-wasmdec/) za dekompajliranje.

Softver:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Keširani bajtkod za Node.js / V8

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

Prednost je u tome što ovaj postupak može uštedeti vreme kada izgubljeni izvorni kôd treba obnoviti iz zastarelog sklopa. Pored toga, dotPeek omogućava praktičnu navigaciju kroz dekompajlirani kôd, što ga čini jednim od idealnih alata za **analizu Xamarin algoritama.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Zahvaljujući sveobuhvatnom modelu dodataka i API-ju koji omogućava da alat prilagodite svojim potrebama, .NET Reflector štedi vreme i pojednostavljuje razvoj. Pogledajmo brojne usluge za reverse engineering koje ovaj alat pruža:

- Pruža uvid u tok podataka kroz biblioteku ili komponentu
- Pruža uvid u implementaciju i upotrebu .NET jezika i okvira
- Pronazi nedokumentovanu i neizloženu funkcionalnost kako biste bolje iskoristili API-je i korišćene tehnologije.
- Pronazi zavisnosti i različite sklopove
- Pronalazi tačnu lokaciju grešaka u vašem kôdu, komponentama trećih strana i bibliotekama.
- Omogućava otklanjanje grešaka u izvornom kôdu svih .NET programa sa kojima radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) i [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy dodatak za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga instalirati direktno iz VSCode-a; nema potrebe da preuzimate git. Kliknite na **Extensions** i **potražite ILSpy**).\
Ako treba da **dekompajlirate**, **izmenite** i ponovo **kompajlirate**, možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegov aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknite desnim tasterom -> Modify Method** da biste nešto promenili unutar funkcije).

### Pregled upravljanog kôda bez izvršavanja uz REA

**REA** može da pregleda PE/CLI metapodatke i CIL bez učitavanja sklopa. Započnite identifikacijom artefakta, a zatim pregledajte članove i deklarisane granice nativnog kôda; ovo je korisno pri proveri sumnjivih poziva pre korišćenja dekompajlera ili pokretanja programa.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Za poređenje verzija, `compare_managed_members` koristi sirovi CIL/identitet potpisa i otiske dekodiranih instrukcija, umesto da tretira metadata tokene kao stabilne između buildova. P/Invoke deklaracija nije dokaz da je native kod izvršen; `verify_managed_native_boundaries` zahteva odgovarajući native export ili dokaz funkcije da bi proverio tu granicu. Sačuvajte digest artefakta, MVID i nerazrešena mapiranja uz rezultat.<sup>[[17]](#references)</sup>

### DNSpy logovanje

Da biste podesili da **DNSpy zapisuje neke informacije u datoteku**, možete da koristite ovaj isečak:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Otklanjanje grešaka u DNSpy

Da biste otklanjali greške u kodu pomoću DNSpy-ja, potrebno je da:

Najpre promenite **Assembly attributes** koji se odnose na **debugging**:

![DNSpy Logging - Otklanjanje grešaka u DNSpy: Najpre promenite Assembly attributes koji se odnose na debugging](<../../images/image (973).png>)

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

Ovo je neophodno jer će se, ako to ne uradite, tokom **runtime**-a na kod primeniti nekoliko **optimizacija**, pa je moguće da se tokom debagovanja **break-point nikada ne aktivira** ili da neke **promenljive ne postoje**.

Zatim, ako vašu .NET aplikaciju pokreće **IIS**, možete da je **restartujete** pomoću:

```
iisreset /noforce
```

Zatim, da biste započeli debugovanje, zatvorite sve otvorene datoteke i na kartici **Debug** izaberite **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste započeli debugovanje, zatvorite sve otvorene datoteke i na kartici Debug izaberite Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste se povezali sa **IIS serverom** i kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste se povezali sa IIS serverom i kliknite na attach](<../../images/image (113).png>)

Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na _Debug >> Break All_, a zatim na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u prozoru **Modules** i izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u prozoru Modules i izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom miša na bilo koji modul u **Assembly Explorer** i kliknite na **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom miša na bilo koji modul u Assembly Explorer i kliknite na Sort Assemblies](<../../images/image (339).png>)

## Java dekompajler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugovanje DLL-ova

### Korišćenje IDA

- **Učitajte rundll32** (64-bitna verzija je u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- Izaberite debugger **Windbg**
- Izaberite "**Suspend on library load/unload**"

![Debugovanje DLL-ova - Korišćenje IDA: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Podesite **parametre** izvršavanja tako što ćete uneti **putanju do DLL-a** i funkciju koju želite da pozovete:

![Debugovanje DLL-ova - Korišćenje IDA: Podesite parametre izvršavanja tako što ćete uneti putanju do DLL-a i funkciju koju želite da pozovete](<../../images/image (704).png>)

Zatim, kada započnete debugovanje, **izvršavanje će se zaustaviti pri učitavanju svakog DLL-а**. Dakle, kada rundll32 učita vaš DLL, izvršavanje će se zaustaviti.

Ovaj metod se zaustavlja pri događajima učitavanja modula, ali dolazak do ulazne tačke učitanog DLL-а manje je direktan nego u x64dbg postupku u nastavku.

### Korišćenje x64dbg/x32dbg

- **Učitajte rundll32** (64-bitna verzija je u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- **Promenite Command Line** ( _File --> Change Command Line_ ) i unesite putanju DLL-a i funkciju koju želite da pozovete, na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Promenite _Options --> Settings_ i izaberite "**DLL Entry**".
- Zatim **pokrenite izvršavanje**. Debugger će se zaustavljati na svakom dll main-u i u nekom trenutku će se **zaustaviti na ulaznoj tački vašeg DLL-a**. Odatle samo potražite mesta na koja želite da postavite breakpoint.

Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg, na **vrhu prozora win64dbg** možete videti **u kom se kodu nalazite**:

![Korišćenje IDA - Korišćenje x64dbg/x32dbg: Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg, na vrhu prozora win64dbg možete videti u kom se kodu nalazite](<../../images/image (842).png>)

Ovaj indikator potvrđuje da se izvršavanje zaustavilo unutar DLL-а koji želite da debugujete.

## GUI aplikacije / video-igre

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje mesta u memoriji aktivne igre na kojima se čuvaju važne vrednosti, kao i za njihovu izmenu. Više informacija:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end/alat za reverse engineering za GNU Project Debugger (GDB), namenjen igrama. Međutim, može se koristiti za bilo šta povezano sa reverse engineeringom.

[**Decompiler Explorer**](https://dogbolt.org/) je web front-end za više dekompajlera. Ova web usluga omogućava poređenje izlaza različitih dekompajlera za male izvršne datoteke.

### Dešifrovanje Godot PCK datoteka i oporavak projekta

Za distribuiranu Godot igru pronađite njenu PCK datoteku kao samostalnu `.pck` datoteku, dodatni ili ugrađeni paket u izvršnoj datoteci ili u direktorijumu `assets` u APK-u. [gore](https://github.com/figurophobia/gore) može da pregleda i izdvoji paket, dok je za potpunu rekonstrukciju skripti i resursa potreban GDRE Tools (`gore setup` ga instalira, ili možete da koristite `--gdre`). Alat podržava Godot 4.x PCK formate v2–v4 za ovaj postupak; može da prepozna zaglavlja v1, ali je za v1 potrebno dostaviti ključ.<sup>[[25]](#references)</sup>

Automatski oporavak ključa zahteva šifrovanu tabelu datoteka. Ako je šifrovan samo sadržaj datoteka, navedite poznati ključ. Neuspešan oporavak ne znači da paket nije šifrovan.<sup>[[28]](#references)</sup>

Pretraga ključa **nije napad na prostor ključeva AES-256**. Šifrovana tabela datoteka otkriva MD5 sažetak svog otvorenog teksta, dužinu otvorenog teksta, IV i AES-256-CFB šifrat.<sup>[[27]](#references)</sup> `gore` testira prozore od 32 bajta iz izvršne datoteke igre ili susednih datoteka kao moguće ključeve. Filtrira kandidate na osnovu verovatne dužine i prefiksa dešifrovane putanje, a zatim potvrđuje pogotke pronađene binarnim skeniranjem tako što dešifruje celu tabelu i proverava njen MD5 sažetak.<sup>[[26]](#references)[[28]](#references)</sup> Najpre pretražuje inicijalizovane PE/ELF odeljke sa podacima, a zatim prelazi na skeniranje cele datoteke; `--scan` dodaje druge datoteke kandidatkinje.<sup>[[28]](#references)</sup>

Ako ugrađeni ključ nije pronađen, isprobava se mala ugrađena lista lozinki; `--wordlist` omogućava da navedete druge kandidate. Svaka lozinka se testira kao predstavljanje ključa izvedeno iz lozinke koje koristi engine, kao literal dopunjen nul-bajtovima ili kao ključ od 64 heksadecimalna znaka. Za razliku od pogodaka pronađenih binarnim skeniranjem, pogoci iz wordlist-a u ovoj implementaciji prolaze samo proveru strukture putanje. Potvrdite ih tako što ćete otvoriti paket i proveriti izdvojene resurse.<sup>[[26]](#references)[[28]](#references)</sup>

Kada je artefakt igre dostupan lokalno, izaberite fazu koja vam je potrebna za analizu. `recover` poziva GDRE da rekonstruiše projekat koji se može otvoriti, dok `extract` samo raspakuje sirove datoteke. `key` ispisuje mogući ključ koji možete koristiti sa drugim alatom.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Istraga nativnog koda zasnovana na dokazima uz REA

**REA** omogućava analizu u Hopper, Ghidra i IDA alatima putem CLI-ja i MCP-a. Potreban je Node.js 22.x (najmanje 22.19), 24.x (najmanje 24.11) ili 26+, kao i npm. Najpre konfigurišite postojećeg nativnog provajdera; proverite `rea providers --json` i izaberite provajdera izričito ako ih više podržava cilj. Umesto `0x1000` u nastavku koristite naziv funkcije ili adresu zabeleženu u inventaru.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Počnite od niza funkcija ili simbola, pratite reference i pozivaoce, a zatim pregledajte dosije izabrane funkcije i pseudokod pomoću `rea decompile`. REA vezuje sesiju za izabranog provajdera, umesto da ga neprimetno zameni nakon neuspeha. Za ponovljive upite, `--snapshot PATH` ponovo koristi samo bajtove artefakata, provajdera, podešavanja, operaciju i parametre koji se poklapaju; snapshot je lokalni keš, a ne sačuvana baza podataka provajdera. Sačuvajte vraćeni Evidence i eksplicitno navedene nepoznanice, umesto da izvedene putanje ili tekst dekompilatora tretirate kao izvorni kod.<sup>[[16]](#references)[[18]](#references)</sup>

Za JavaScript/Electron ulazne tačke koje vode do native dodataka, pogledajte [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Skriptovana analiza u IDA-i i Ghidri pomoću lokalnog TCP bridge-a

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) radi unutar **već otvorene** IDA baze podataka ili Ghidra CodeBrowser programa i omogućava zasebnoj skripti da ispituje i menja tu bazu analize. Pokrenite `ID_Server.py` iz IDA-inog Python CLI-ja (`import ID_Server`) ili `Ghidra_Server.py` iz Ghidra Script Manager-a. IDA se vezuje za `127.0.0.1`, počevši od porta `5073`, i proverava više portove. Trenutna Ghidra skripta počinje od porta `5093` i pokušava deset portova do `5102`; njen Java socket se vezuje za wildcard adresu, a ne samo za loopback. Pre povezivanja proverite port koji ispisuje instanca. Za razliku od headless analyzer-a, ovaj bridge radi nad programom koji je trenutno otvoren u toj GUI instanci.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Pošaljite **jednu komandu završenu znakom za novi red po vezi** i pročitajte odgovor završen znakom za novi red. Rezultat je obično JSON. Na primer, nakon što pronađete uvezeni API relevantan za ulaznu putanju, `IMPORTXREF` pronalazi mesta na kojima se on poziva; zatim `DECOMP_XREF` grupno dekompajlira pozivaoce izabrane adrese. `FUNC` ispituje funkciju, dok `PCODE` vraća posredni prikaz dekompilatora. Koristite adresu iz aktivne baze podataka, a ne adresu prekopiranu iz binarne datoteke sa drugačijom baznom adresom. Primer ispod koristi podrazumevani IDA port; za Ghidru koristite port koji ispisuje njena skripta.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Isti kanal može da **menja bazu podataka za analizu**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` i `PATCH` menjaju nazive, tipove, definicije struktura, granice funkcija ili sačuvane bajtove. `PATCH` je izmena baze podataka, **a ne** dokaz da je izvršena izmena procesa uživo. Nijedan listener ne dokumentuje autentifikaciju. IDA prihvata veze samo preko loopback interfejsa, ali Ghidra može biti dostupna preko mrežnih interfejsa; ograničite pristup Ghidra listeneru kada ga koristite. `QUIT` zaustavlja bilo koji od listenera, a IDA takođe izlaže `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugovanje shellcode-a pomoću BlobRunner-a

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alocira **shellcode**, ispisuje njegovu **memorijsku adresu** i pauzira izvršavanje.\
Prikačite debugger kao što su IDA ili x64dbg, postavite breakpoint na ispisanu adresu i nastavite izvršavanje da biste debugovali shellcode.

GitHub stranica sa izdanjima sadrži ZIP arhive sa kompajliranim izdanjima: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Neznatno izmenjenu verziju Blobrunner-a možete pronaći na sledećem linku. Da biste je kompajlirali, samo **napravite C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod i izgradite ga**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugovanje shellcode-a pomoću jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je sličan BlobRunner-u. Alocira shellcode i ulazi u beskonačnu petlju. Prikačite debugger, nastavite izvršavanje na **2–5 sekundi**, pauzirajte unutar te petlje i izvršite korak do sledećeg poziva koji prenosi izvršavanje na alocirani shellcode.

![Debugger je pauziran u beskonačnoj petlji jmp2it-a, neposredno pre poziva alociranog shellcode-a](<../../images/image (509).png>)

Kompajliranu verziju [jmp2it-a možete preuzeti sa stranice sa izdanjima](https://github.com/adamkramer/jmp2it/releases/).

### Debugovanje shellcode-a pomoću Cutter-a

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI za radare. Pomoću Cutter-a možete emulirati shellcode i dinamički ga ispitivati.

Imajte na umu da Cutter omogućava izbor opcije „Open File“ i „Open Shellcode“. U mom slučaju, kada sam otvorio shellcode kao datoteku, ispravno ga je dekompilovao, ali kada sam ga otvorio kao shellcode, nije:

![Cutter prikazuje različite rezultate analize kada se isti bajtovi otvore kao datoteka ili kao shellcode](<../../images/image (562).png>)

Da biste pokrenuli emulaciju na željenom mestu, postavite bp na to mesto; izgleda da će Cutter automatski pokrenuti emulaciju odatle:

![Postavljanje breakpoint-a na željeni ulaz shellcode-a pre pokretanja Cutter emulacije](<../../images/image (589).png>)

![Cutter emulator je pauziran na izabranom breakpoint-u shellcode-a](<../../images/image (387).png>)

Na primer, stek možete videti unutar hex dump-a:

![Pregled steka emuliranog shellcode-a u Cutter-ovom hex dump-u](<../../images/image (186).png>)

### Deobfuskacija shellcode-a i pronalaženje izvršenih funkcija

Trebalo bi da isprobate [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Pokazaće vam stvari kao što su **koje funkcije** shellcode koristi i da li se shellcode **dekodira** u memoriji.

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

Opcija **Create Dump** pravi dump konačnog shellcode-a ako se on dinamički promeni u memoriji (korisno za preuzimanje dekodiranog shellcode-a). **start offset** može biti koristan za pokretanje shellcode-a od određenog offset-a. Opcija **Debug Shell** korisna je za debagovanje shellcode-a pomoću scDbg terminala (međutim, smatram da je bilo koja od prethodno objašnjenih opcija bolja za to, jer ćete moći da koristite Ida ili x64dbg).

### Disasembliranje pomoću CyberChef-a

Otpremite datoteku sa shellcode-om kao ulaz i koristite sledeći recept da biste ga dekompilirali: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskacija MBA obfuskacije

Obfuskacija **Mixed Boolean-Arithmetic (MBA)** skriva jednostavne izraze poput `x + y` iza formula koje kombinuju aritmetičke (`+`, `-`, `*`) i bitovne operatore (`&`, `|`, `^`, `~`, shifts). Važno je da su ovi identiteti obično tačni samo u okviru **modularne aritmetike fiksne širine**, tako da su prenosi i prekoračenja bitni:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ako ovaj tip izraza pojednostavite generičkim alatima za algebru, lako možete dobiti pogrešan rezultat jer semantika širine bitova nije uzeta u obzir.<sup>[[1]](#references)</sup>

### Praktični tok rada

1. **Zadržite originalnu širinu bitova** iz izlaza podignutog koda/IR-a/dekompilatora (`8/16/32/64` bitova).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
   - **Linearni**: ponderisani zbirovi bitovskih atoma
   - **Semilinearni**: linearni izrazi uz konstantne maske kao što je `x & 0xFF`
   - **Polinomski**: pojavljuju se proizvodi
   - **Mešoviti**: proizvodi i bitovska logika su isprepletani, često uz ponovljene podizraze
3. **Proverite svaku predloženu transformaciju** nasumičnim testiranjem ili SMT dokazom. Ako se ekvivalentnost ne može dokazati, zadržite originalni izraz umesto da nagađate.

### Zaobiđite spljošteni tok kontrole pomoću uskog izvršnog isečka

Često nije potrebno rekonstruisati ceo graf toka kontrole. Kod spljoštavanja toka kontrole, neprozirnih predikata, velikih dispečera ili koda sa mnogo MBA izraza, pratite reference od šifrovanih blobova i izlaznih bafera do najmanje rutine koja ih transformiše. Zatim reprodukujte samo taj isečak toka podataka ili ga izvršite nezavisno; dispečer nije deo potrebnog rešenja ako se relevantno stanje može direktno inicijalizovati.<sup>[[7]](#references)</sup>

Praktični tok rada je:<sup>[[7]](#references)</sup>

1. Popišite izvršne sekcije i sekcije sa podacima, relokacije i unakrsne reference. Izbacite kandidate za tabele iz `.rodata`, uz očuvanje redosleda bajtova i širine elemenata.
2. Pronađite poslednju rutinu koja upisuje čist tekst ili izlazni bafer. Zabeležite njene ulaze, tabele na koje se poziva, uvezene pozive i potrebno globalno stanje.
3. Podignite samo te operacije u model sa fiksnom širinom u Pythonu. Ako isečak i dalje zavisi od previše stanja, pozovite rutinu pomoću Unicorn-a, QEMU-a ili debagera i zakačite nebitne uvezene funkcije umesto da emulirate ceo program.
4. Proverite da ekstraktor zaista izvodi svoj izlaz iz dostavljenog binarnog fajla: uklonite tihe rezervne opcije, pretražite ga u potrazi za ugrađenim odgovorima i pokrenite ga na neviđenim verzijama sa izmenjenim stringovima, ključevima, identifikatorima, rasporedima i seed-ovima za obfuskaciju.

Korisne naredbe za prvi prolaz su:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Otkrivanje MBA izraza koji prikrivaju konstante

Izraz za bajt koji naizgled zavisi od ulaza može potpuno poništiti svoj ulaz. Nakon izdvajanja njegovih tabela, evaluirajte izraz za ceo 8-битни домен; једночлани скуп излаза доказује да је тај бајт константан, без потребе да се реконструише околна машина стања.<sup>[[7]](#references)</sup>

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

Zadržite završnu masku jer izvorno sabiranje ima prelivanje pri širini bajta. Za širi domen pitajte SMT solver da li je izraz `f(x1) != f(x2)` zadovoljiv za dva simbolička ulaza iste širine: `unsat` dokazuje invarijantnost, dok `sat` daje kontraprimer i znači da se ulaz ne može odbaciti.<sup>[[7]](#references)</sup>

#### Prepoznajte dekodiranje vezano za okruženje

Provere protiv analize ne moraju da granaju tok izvršavanja niti da izazovu pad. Dekoder može da umeša rezultat senzora u bit ključa, konstantu opaque-predicate-a ili stanje flattened-dispatcher-a, nastavi normalno i u emulatoru proizvede uverljiv, ali netačan otvoreni tekst. Zato nije dovoljno zakrpiti samo vidljive grane koje izazivaju grešku; pratite zavisnosti podataka od proba okruženja do stanja dekodera, uporedite isti isečak na autentičnom uređaju i emulatoru i proverite kako forsiranje svakog rezultata senzora menja završni bafer.<sup>[[7]](#references)</sup>

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

- **Linear MBA**: CoBRA evaluira izraz nad Booleovim ulazima, izvodi potpis i paralelno pokreće nekoliko metoda za rekonstrukciju, kao što su uparivanje obrazaca, konverzija u ANF i interpolacija koeficijenata.
- **Semilinear MBA**: atomi maskirani konstantama ponovo se izgrađuju rekonstrukcijom podeljenom po bitovima, tako da maskirane oblasti ostanu ispravne.
- **Polynomial/Mixed MBA**: proizvodi se rastavljaju na jezgra, a ponovljeni podizrazi mogu se izdvojiti u privremene promenljive pre pojednostavljivanja spoljne relacije.

Primer mešovitog identiteta koji često vredi pokušati rekonstruisati:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Ovo se može svesti na:

```c
x * y
```

### Beleške o reverznom inženjerstvu

- Prednost dajte pokretanju CoBRA nad **podignutim IR izrazima** ili izlazom dekompilatora nakon što izdvojite tačno izračunavanje.
- Koristite `--bitwidth` izričito kada je izraz nastao iz maskirane aritmetike ili registara manje širine.
- Ako vam je potreban jači korak dokazivanja, pogledajte lokalne beleške o Z3 ovde:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA se isporučuje i kao dodatak za LLVM pass (`libCobraPass.so`), koji je koristan kada želite da normalizujete LLVM IR sa mnogo MBA pre kasnijih faza analize.
- Ostatke mešovitih domena osetljive na prenos, koje alat ne podržava, treba smatrati signalom da zadržite originalni izraz i ručno analizirate put prenosa.

## Rekonstrukcija kontrole toka sa spljoštavanjem i XOR-stanjem

Spljoštavanje u stilu OLLVM-a može čuvati stanje trenutnog osnovnog bloka u dva 64-bitna registra i rekonstruisati ga pomoću XOR-a u dispečeru. Svaki originalni blok upisuje par koji predstavlja sledeće stanje i skače nazad u dispečer. Uslovni blok može da koristi `CMOVcc` da zameni jednu polovinu para u zavisnosti od CPU zastavica, pa praćenjem samo vidljivih instrukcija grananja promaknu oba naslednika. Za razliku od dispečera sa indirektnim skokom, ovaj oblik može svuda da koristi direktne povratne grane.<sup>[[19]](#references)[[20]](#references)</sup>

Da biste rekonstruisali graf, pronađite stablo poređenja u dispečeru i dva registra stanja, povežite svako poređeno XOR stanje sa ciljnim blokom, a zatim pratite upise u par registara koji dopiru do svake originalne osnovne blokovske celine. Kod uslovnih upisa uključite instrukciju koja postavlja zastavice i oba ishoda `CMOVcc`. Zamenite izlaz svakog bloka ka dispečeru njegovim razrešenim direktnim naslednikom ili uslovnim grananjem; dispečer će tada postati nedostižan bez izmene binarne datoteke. Ovo je pristup koji obuhvata ceo CFG; ako je važan samo jedan dekoder, [tok rada sa uskim izvršnim isečkom](#bypass-flattened-control-flow-with-a-narrow-execution-slice) iznad može biti brži.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatizuje ovaj oblik u Binary Ninja. Kopirajte `plugins/DispatchThis` u korisnički direktorijum dodataka za Binary Ninja i ponovo pokrenite program. Za pogođenu funkciju otvorite **Function Settings** i izaberite `OLLVM_XOR_64`; ako analiza ne počne, upotrebite **Analysis → Reanalyze All Functions**. Ovaj režim prepisuje ivice kontrole toka u MLIL-u, a ne bajtove datoteke, i ne zahteva Z3 niti razrešivač indirektnih skokova. Testiran je u Binary Ninja 5.3.9757+; ne uklanja mrtve upise stanja po blokovima, zato ih nemojte pogrešno smatrati preostalim aktivnim prelazima.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuskator zamenjuje programske operacije sekvencama instrukcija zasnovanim na `mov` i koristi rukovanje signalima/izuzecima za izmenu kontrole toka. Detalji:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Za podržane binarne datoteke, [demovfuscator](https://github.com/kirschju/demovfuscator) može da deobfuskuje rezultat. Ima nekoliko zavisnosti.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

I [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako učestvujete u **CTF-u, ovo zaobilazno rešenje za pronalaženje flag-a** može biti veoma korisno: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **ulaznu tačku**, pretražite funkcije po `::main`, kao u primeru:

![Pronalaženje ulazne tačke Rust programa u Ghidra-i pretragom naziva funkcija za dvotačku i main](<../../images/image (1080).png>)

U ovom slučaju binarna datoteka se zvala authenticator, tako da je prilično očigledno da je ovo zanimljiva main funkcija.\
Kada saznate **nazive** pozivanih **funkcija**, potražite ih na **Internetu** da biste saznali njihove **ulaze** i **izlaze**.

### Vraćanje Rust stringova iz ELF firmware-a

U **Rust ELF** binarnim datotekama, mnogi statički stringovi nisu referencirani kao pokazivači sa završnim NUL znakom u C stilu. Uobičajeni raspored koji koristi `rustc` jeste **torka pokazivača i dužine** unutar **`.data.rel.ro`**, koja pokazuje na stvarni blok stringova smešten u **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

To znači da `strings` ili podrazumevana analiza u Ghidri mogu spojiti susedne stringove ili potpuno propustiti unakrsne reference.<sup>[[3]](#references)</sup>

Brzi postupak:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Odredite virtuelnu adresu i veličinu odeljka **`.rodata`**.
2. Enumerišite **`.data.rel.ro`** reč po reč.
3. Svaku vrednost koja se nalazi u opsegu adresa odeljka `.rodata` tretirajte kao kandidata za pokazivač na string.
4. Sledeću reč tretirajte kao kandidatsku dužinu.
5. Primenite razumne filtere (na primer, zadržite dužine između **4** i **100** bajtova).
6. Iz `.rodata` pročitajte tačno `length` bajtova umesto da skenirate do `0x00`.

Minimalna logika ekstraktora:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Ovo je naročito korisno pri reversing-u firmware-a, jer izdvojeni Rust stringovi često otkrivaju **HTTP rute, RPC nazive, log poruke, provere, nazive datoteka, konfiguracione ključeve, obrađivače komandi i logiku povezanu sa autentifikacijom**.

Ako Ghidra ne pronađe te stringove, pokrenite prilagođenu skriptu/plugin koji primenjuje istu heuristiku i kreira string podatke na referenciranim `.rodata` pomerajima. Objavljeni alati `rust-strings` i `RustStrings.py` kompanije Pen Test Partners korisni su kao primeri za prilagođavanje ove ideje drugim **veličinama reči, redosledima bajtova i rasporedima sekcija**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Za binarne datoteke kompajlirane za Delphi možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako treba da izvršite reversing Delphi binarne datoteke, predlažem da koristite IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pritisnite **Alt+F7** u IDA-i da biste učitali Python plugin, a zatim izaberite datoteku plugina.

Ovaj plugin će izvršiti binarnu datoteku i dinamički razrešiti nazive funkcija na početku otklanjanja grešaka. Nakon što pokrenete otklanjanje grešaka, ponovo pritisnite dugme Start (zeleno dugme ili f9) i izvršiće se breakpoint na početku stvarnog koda.

Ako pritisnete dugme u grafičkoj aplikaciji, debugger se može zaustaviti u funkciji koju to dugme poziva.

## Golang

Za uobičajene Go binarne datoteke, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) može da povrati runtime strukture i poboljša nazive funkcija u IDA-i. Učitajte njegov Python plugin pomoću **Alt+F7**.

Ako treba da izvršite reversing Golang binarne datoteke, predlažem da koristite IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pritisnite **Alt+F7** u IDA-i da biste učitali Python plugin, a zatim izaberite datoteku plugina.

Ovo će razrešiti nazive funkcija.

### Oporavljanje metapodataka bez tabele simbola

Izvršna Go datoteka iz koje su uklonjeni simboli i dalje zahteva runtime metapodatke za mapiranje programskih brojača na funkcije. [GoReSym](https://github.com/mandiant/GoReSym) pronalazi i parsira strukture kao što su `pclntab` i `moduledata` koristeći kod izveden iz Go runtime-a. Ovo može da povrati granice funkcija, nazive, izvorne putanje, tipove i detalje o izgradnji bez oslanjanja na konvencionalnu tabelu simbola.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator može da ostavi te strukture upotrebljivim, a da zameni pronađena imena. Na primer, Garble hešira identifikatore i putanje paketa i uklanja informacije o izgradnji, modulima i otklanjanju grešaka.<sup>[[12]](#references)</sup> Obfuskirani token paketa mora da ostane isti u svim funkcijama iz tog paketa. Grupirajte funkcije prema ponovljenom tokenu, zaključite o kom paketu je reč na osnovu funkcija koje pozivaju, stringova i API-ja, a zatim dodelite oznaku tog paketa celoj grupi.<sup>[[13]](#references)</sup>

### Oporavite Garble imena pomoću GoResolver-a

[GoResolver](https://github.com/volexity/GoResolver) objedinjuje izdvajanje simbola iz vremena izvršavanja, generisanje čistih referenci i upoređivanje grafova toka kontrole (CFG). Koristite sledeći redosled:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifikujte verziju kompajlera.** Najpre pokušajte sa `BuildInfo` i ugrađenim stringovima verzije. Ako ih je obfuskator uklonio, uporedite delove ugrađenog Go runtime-a sa referentnim runtime-ovima po verzijama. U Volexity testovima bilo je dovoljno oko `2%` runtime-a da se razlikuju glavne Go verzije. Ovo tretirajte kao empirijsku optimizaciju, a ne kao univerzalni prag.<sup>[[13]](#references)</sup>
2. **Napravite odgovarajuće reference.** Generišite čiste binarne datoteke za identifikovanu verziju Go-a, ciljnu arhitekturu i verovatne biblioteke. Usklađivanje toolchain-a smanjuje razlike u CFG-u koje stvara kompajler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Uporedite funkcije.** GoGrapher upoređuje CFG-ove funkcija i daje normalizovane ocene od `0.0` do `1.0`. Njegovo upoređivanje osnovnih blokova zasniva se na ponderisanom poređenju sličnih instrukcija. Poklapanja sa visokim stepenom pouzdanosti povezuju randomizovane funkcije sa čistom implementacijom. Slabija poklapanja i dalje mogu da identifikuju paket ili modul.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Proverite i uvezite rezultate.** Potvrdite predložena imena na osnovu odnosa poziva, konstanti, stringova i sporednih efekata, a zatim uvezite JSON izveštaj pomoću GoResolver dodatka za IDA ili Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instalirajte toolchain i pokrenite kombinovani alat za izdvajanje i upoređivanje grafova:<sup>[[10]](#references)</sup>

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

Podrazumevani prag značajnog poklapanja je `0.9`. Opcije `--extract` i `--graph` mogu da izdvoje bilo koju od faza, dok se podrazumevano pokreću obe, jer se oporavljeni runtime metapodaci i dokazi iz CFG-a međusobno dopunjuju.<sup>[[10]](#references)</sup> CFG ocene su heurističke: inlining, build zastavice, arhitektura i razlike u verzijama biblioteka mogu da promene oblik grafa, zato zadržite nerazrešene funkcije umesto da im dodeljujete nazive sa niskim stepenom pouzdanosti.<sup>[[13]](#references)</sup>

### Oporavak Go tabele stringova

Go binarni fajlovi smeštaju bajtove stringova iz svih povezanih paketa u jednu neprekidnu tabelu. Unosi se ne završavaju nulom, a runtime strukture ne otkrivaju osnovnu adresu ni veličinu tabele. Međutim, kompajler na svim operativnim sistemima i arhitekturama prvo sortira unose po dužini, a zatim po abecedi. Zato analitičar, nakon pronalaženja jednog unosa, može da prolazi kroz susedne unose i koristi unakrsne reference podataka da poveže stringove sa kodom.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatizuje ovaj postupak u IDA Pro i Ghidra. Najpre sačekajte da se završi automatska analiza jer se dodatak oslanja na unakrsne reference segmenata podataka. Podrazumevano koristi runtime string `entersyscall` kao sidro, a zatim može da pretražuje u oba smera, definiše oporavljene stringove u bazi podataka i izveze JSON mapiranje stringova na funkcije koje ih referenciraju.<sup>[[14]](#references)</sup>

Filtrirajte izveštaj prema paketu funkcije koja referencira string kako biste razdvojili kod aplikacije ili malvera od šuma povezanih biblioteka. Ova tehnika ne može da oporavi literale uništene obfuskacijom, kao što je Garbleova transformacija `-literals`. I dalje može da organizuje runtime stringove koji su ostali neobfuskovani.<sup>[[14]](#references)[[15]](#references)</sup>

### Oporavak Go runtime tipova

Go ugrađuje informacije o runtime tipovima koje koriste funkcije kao što je garbage collection. Kada su build informacije uklonjene ili disassembler ne raščlanjuje ove metapodatke, može izgledati da instrukcije učitavaju proizvoljne adrese podataka, a ciljni region ostaje netipizovan. Oporavak metapodataka pretvara te adrese u čitljive reference na tipove i olakšava razumevanje mogućnosti paketa.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) može da izdvoji simbole i raščlani runtime tipove u JSON izveštaj. Trenutni CLI koristi podkomandu `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Opcija `-y`/`--types` omogućava parsiranje tipova. Uvezite izveštaj pomoću GoResolver-ovog dodatka za IDA Pro ili Ghidru da biste definisali oporavljene tipove i primenili njihove reference u bazi podataka analize. U formatu izveštaja uvedenom ovom funkcijom, izostavljanje opcije `-y` ostavlja članove RTTI adrese i oporavljenih tipova kao null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver podržava uzorke PE, ELF i Mach-O za x86, AMD64, ARM i ARM64, tako da se isti postupak primenjuje na Go binarne datoteke iz Windowsa, Linuxa i macOS-a.<sup>[[10]](#references)</sup>

## Kompajlirani Python

Na ovoj stranici možete pronaći kako da dobijete Python kod iz kompajlirane Python binarne datoteke ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ako dobijete **binarnu datoteku** igre za GBA, možete koristiti različite alate za njenu **emulaciju** i **debugovanje**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite verziju za debugovanje_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra dodatak
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra dodatak

U programu [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_** ** možete videti kako da pritisnete dugmad za Game Boy Advance

![Konfiguracija kontrola u no$gba prikazuje mapiranje dugmadi za Game Boy Advance](<../../images/image (581).png>)

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

Dakle, u ovakvoj vrsti programa zanimljiv deo biće **način na koji program obrađuje korisnički unos**. Na adresi **0x4000130** pronaći ćete često prisutnu funkciju: **KEYINPUT**.

![Ghidra prikaz GBA binarne datoteke koja upućuje na KEYINPUT na adresi 0x4000130](<../../images/image (447).png>)

Na prethodnoj slici možete videti da se funkcija poziva iz **FUN_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekih inicijalizacionih operacija (koje nisu važne):

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

Poslednji if proverava da li se **`uVar4`** nalazi među **poslednjim tasterima** i nije trenutni taster; to se naziva otpuštanjem tastera (trenutni taster je sačuvan u **`uVar1`**).

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

- Prvo se upoređuje sa **vrednošću 4** (dugme **SELECT**): u ovom izazovu ovo dugme briše ekran.
- Zatim se vrednost upoređuje sa **8** (dugme **START**); u ovom izazovu, ta grana proverava da li je uneti kod važeći.
  - U ovom slučaju, varijabla **`DAT_030000d8`** se upoređuje sa 0xf3 i, ako su vrednosti iste, izvršava se određeni kod.
- U svim ostalim slučajevima proverava se brojač (`DAT_030000d4`) i uvećava.\
  Dok je brojač manji od 8, vrednosti pritisnutih dugmadi se sabiraju u `DAT_030000d8`.

Dakle, u ovom izazovu, znajući vrednosti dugmadi, trebalo je da **pritisnete kombinaciju kraću od 8 dugmadi čiji je zbir 0xf3.**

**Referenca za ovaj vodič:** [arhivirani opis rešenja izazova Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursevi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binarnа deobfuskacija)

## References

- [1] [Pojednostavljivanje MBA obfuskacije pomoću CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repozitorijum](https://github.com/trailofbits/CoBRA)
- [3] [Dekodiranje Rust stringova - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - Rust stringovi](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - vodič za GBA reversing (arhiviran)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Poraziti AI-potpomognuti reverse engineering — ili bar pokušati](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Pristup poređenju grafova toka kontrole zasnovan na uparivanju osnovnih blokova](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repozitorijum](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mehanizam obfuskacije Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: korišćenje sličnosti grafova toka kontrole za automatsku deobfuskaciju Golang binarnih datoteka](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repozitorijum](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: novosti o Volexity alatima za Golang](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: obrnuti inženjering bilo čega](https://github.com/morluto/rea)
- [17] [REA analiza upravljanog koda](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI i vodič za dokaze](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja tok rada za uklanjanje spljoštavanja toka kontrole](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: upad u PaperCut MF nultog dana, Java loader, web shell i AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementacija IDA bridge servera](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementacija Ghidra bridge servera](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) se vezuje za wildcard adresu](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Godot alat za reverse engineering](https://github.com/figurophobia/gore)
- [26] [gore implementacija oporavka ključa](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [gore format šifrovanog blob-a](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [gore implementacija komande i oporavka](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
