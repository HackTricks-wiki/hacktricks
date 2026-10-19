# Alati za reversing i osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## Alati za reversing zasnovani na ImGui

Softver:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automatizacija WinDbg-a u user-mode režimu

{{#ref}}
windbg-automation.md
{{#endref}}

## Debugovanje Windows kernela

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm dekompilator / Wat kompajler

Na mreži:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) za **dekompilaciju** iz wasm (binarnog formata) u wat (čitljiv tekst)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) za **kompilaciju** iz wat u wasm
- Za dekompilaciju možete isprobati i [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Softver:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Keširani bytecode za Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtuelizovani payload-i i prilagođene VM-ove

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET dekompilator

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je dekompilator koji **dekompilira i pregleda više formata**, uključujući **biblioteke** (.dll), **Windows metadata fajlove** (.winmd) i **izvršne fajlove** (.exe). Nakon dekompilacije, assembly se može sačuvati kao Visual Studio projekat (.csproj).

Prednost je u tome što ovaj postupak može uštedeti vreme kada je potrebno obnoviti izgubljeni izvorni kod iz zastarelog assembly-ja. Pored toga, dotPeek omogućava praktičnu navigaciju kroz dekompilirani kod, pa je jedan od idealnih alata za **analizu Xamarin algoritama.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Uz sveobuhvatan model dodataka i API koji omogućava prilagođavanje alata vašim tačnim potrebama, .NET Reflector štedi vreme i pojednostavljuje razvoj. Pogledajmo brojne usluge reverse engineeringa koje ovaj alat pruža:

- Omogućava uvid u to kako podaci prolaze kroz biblioteku ili komponentu
- Omogućava uvid u implementaciju i upotrebu .NET jezika i framework-ova
- Pronalazi nedokumentirane i neizložene funkcionalnosti kako biste bolje iskoristili API-je i korišćene tehnologije.
- Pronalazi zavisnosti i različite assembly-je
- Pronalazi tačnu lokaciju grešaka u vašem kodu, komponentama trećih strana i bibliotekama.
- Omogućava debugovanje izvornog koda celokupnog .NET koda sa kojim radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy dodatak za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga instalirati direktno iz VSCode-a, bez potrebe za preuzimanjem git-a. Kliknite na **Extensions** i **potražite ILSpy**).\
Ako treba da **dekompilirate**, **izmenite** i ponovo **kompilirate**, možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegov aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Desni klik -> Modify Method** da biste nešto izmenili unutar funkcije).

### Pregled managed koda pomoću REA bez izvršavanja

**REA** može da pregleda PE/CLI metadata i CIL bez učitavanja assembly-ja. Počnite od identiteta artefakta, a zatim pregledajte članove i deklarisane granice native koda; ovo je korisno pri proveri sumnjivih poziva pre upotrebe dekompilatora ili pokretanja programa.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Za poređenje verzija, `compare_managed_members` koristi sirovi CIL/identitet potpisa i otiske dekodiranih instrukcija, umesto da tretira tokene metapodataka kao stabilne između izgradnji. P/Invoke deklaracija nije dokaz da je nativni kod pokrenut; `verify_managed_native_boundaries` zahteva podudarni nativni izvoz ili dokaz iz funkcije da bi proverio tu granicu. Sačuvajte digest artefakta, MVID i nerazrešena mapiranja uz rezultat.<sup>[[17]](#references)</sup>

### DNSpy Logging

Da bi **DNSpy zabeležio neke informacije u datoteku**, možete da upotrebite ovaj isečak:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugovanje u DNSpy

Da biste otklanjali greške u kodu pomoću DNSpy, potrebno je da:

Prvo promenite **atribute sklopa** koji se odnose na **otklanjanje grešaka**:

![DNSpy Logging - Debugovanje u DNSpy: Prvo promenite atribute sklopa koji se odnose na otklanjanje grešaka](<../../images/image (973).png>)

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

Zatim sačuvajte novu datoteku putem _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Ovo je neophodno jer će se, ako to ne uradite, tokom **runtime**-a primeniti nekoliko **optimizacija** na kod, pa je moguće da se tokom debugovanja **breakpoint nikada ne aktivira** ili da **neke promenljive ne postoje**.

Zatim, ako vašu .NET aplikaciju **pokreće** **IIS**, možete da je **restartujete** pomoću:

```
iisreset /noforce
```

Zatim, da biste započeli debugovanje, zatvorite sve otvorene fajlove i u kartici **Debug Tab** izaberite **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste započeli debugovanje, zatvorite sve otvorene fajlove i u kartici Debug Tab izaberite Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste se povezali sa **IIS serverom** i kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste se povezali sa IIS serverom i kliknite na attach](<../../images/image (113).png>)

Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na _Debug >> Break All_, a zatim na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Prvo kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u **Modules** i izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u Modules i izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom miša na bilo koji modul u **Assembly Explorer** i izaberite **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom miša na bilo koji modul u Assembly Explorer i izaberite Sort Assemblies](<../../images/image (339).png>)

## Java dekompilator

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugovanje DLL-ova

### Korišćenje IDA

- **Učitajte rundll32** (64-bitna verzija se nalazi u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- Izaberite debugger **Windbg**
- Izaberite "**Suspend on library load/unload**"

![Debugovanje DLL-ova - Korišćenje IDA: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Podesite **parametre** izvršavanja tako što ćete navesti **putanju do DLL-a** i funkciju koju želite da pozovete:

![Debugovanje DLL-ova - Korišćenje IDA: Podesite parametre izvršavanja tako što ćete navesti putanju do DLL-a i funkciju koju želite da pozovete](<../../images/image (704).png>)

Zatim, kada započnete debugovanje, **izvršavanje će se zaustaviti pri učitavanju svake DLL datoteke**. Kada rundll32 učita vaš DLL, izvršavanje će se zaustaviti.

Ovaj metod zaustavlja izvršavanje pri događajima učitavanja modula, ali dolazak do ulazne tačke učitanog DLL-a manje je direktan nego u x64dbg postupku u nastavku.

### Korišćenje x64dbg/x32dbg

- **Učitajte rundll32** (64-bitna verzija se nalazi u C:\Windows\System32\rundll32.exe, a 32-bitna u C:\Windows\SysWOW64\rundll32.exe)
- **Promenite komandnu liniju** ( _File --> Change Command Line_ ) i unesite putanju do DLL-a i funkciju koju želite da pozovete, na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Promenite _Options --> Settings_ i izaberite "**DLL Entry**".
- Zatim **pokrenite izvršavanje**. Debugger će se zaustavljati na svakoj dll main funkciji i u nekom trenutku će se **zaustaviti na ulaznoj tački vašeg DLL-a**. Odatle potražite mesta na koja želite da postavite breakpoint.

Imajte na umu da u win64dbg, kada se izvršavanje zaustavi iz bilo kog razloga, možete da vidite **u kom se kodu nalazite** pri **vrhu prozora win64dbg**:

![Korišćenje IDA - Korišćenje x64dbg/x32dbg: Imajte na umu da u win64dbg, kada se izvršavanje zaustavi iz bilo kog razloga, možete da vidite u kom se kodu nalazite pri vrhu prozora win64dbg](<../../images/image (842).png>)

Ovaj indikator potvrđuje da se izvršavanje zaustavilo unutar DLL-a koji želite da debugujete.

## GUI aplikacije / videoigre

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje važnih vrednosti sačuvanih u memoriji pokrenute igre i njihovu promenu. Više informacija:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end/alati za obrnuti inženjering za GNU Project Debugger (GDB), namenjen igrama. Međutim, može se koristiti za bilo šta povezano sa obrnutim inženjeringom.

[**Decompiler Explorer**](https://dogbolt.org/) je web front-end za više dekompilatora. Ova web usluga omogućava poređenje izlaza različitih dekompilatora za male izvršne datoteke.

## Istraživanje nativnog koda potkrepljeno dokazima pomoću REA

**REA** pruža pristup analizama iz Hopper, Ghidra i IDA putem CLI-ja i MCP-a. Potreban je Node.js 22.x (najmanje 22.19), 24.x (najmanje 24.11) ili 26+, kao i npm. Najpre konfigurišite postojećeg nativnog provajdera; proverite `rea providers --json` i izaberite provajdera izričito ako ih više podržava cilj. Umesto `0x1000` u nastavku upotrebite posmatrano ime funkcije ili adresu iz inventara.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Počnite od stringa funkcije ili simbola, pratite reference i pozivače, a zatim pregledajte dosije izabrane funkcije i pseudokod pomoću `rea decompile`. REA vezuje sesiju za izabranog provajdera, umesto da ga neprimetno zameni nakon greške. Za ponovljive upite, `--snapshot PATH` ponovo koristi samo bajtove artefakta, provajdera, podešavanja, operaciju i parametre koji se poklapaju; snapshot je lokalna keš memorija, a ne sačuvana baza podataka provajdera. Sačuvajte vraćeni Evidence i eksplicitno navedene nepoznanice umesto da izvedene putanje ili tekst dekompilatora tretirate kao izvorni kod.<sup>[[16]](#references)[[18]](#references)</sup>

Za JavaScript/Electron ulazne tačke koje vode do native add-on-ova, pogledajte [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Otklanjanje grešaka u shellcode-u pomoću blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alocira **shellcode**, ispisuje njegovu **memorijsku adresu** i pauzira izvršavanje.\
Prikačite debugger kao što su IDA ili x64dbg, postavite breakpoint na ispisanu adresu i nastavite izvršavanje da biste otklonili greške u shellcode-u.

Stranica izdanja na GitHub-u sadrži ZIP arhive sa kompajliranim izdanjima: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blago izmenjenu verziju Blobrunner-a možete pronaći na sledećem linku. Da biste je kompajlirali, samo **napravite C/C++ projekat u Visual Studio Code-u, kopirajte i nalepite kod i izgradite projekat**.


{{#ref}}
blobrunner.md
{{#endref}}

### Otklanjanje grešaka u shellcode-u pomoću jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je sličan BlobRunner-u. Alocira shellcode i ulazi u beskonačnu petlju. Prikačite debugger, nastavite izvršavanje **2–5 sekundi**, pauzirajte u toj petlji i izvršavajte korak po korak do sledećeg poziva koji prenosi izvršavanje na alocirani shellcode.

![Debugger pauziran u beskonačnoj petlji jmp2it-a neposredno pre poziva alociranog shellcode-a](<../../images/image (509).png>)

Kompajliranu verziju [jmp2it-a možete preuzeti sa stranice izdanja](https://github.com/adamkramer/jmp2it/releases/).

### Otklanjanje grešaka u shellcode-u pomoću Cutter-a

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI za radare. Pomoću Cutter-a možete emulirati shellcode i dinamički ga pregledati.

Imajte na umu da Cutter omogućava opcije „Open File” i „Open Shellcode”. U mom slučaju, kada sam otvorio shellcode kao datoteku, pravilno ga je dekompilirao, ali kada sam ga otvorio kao shellcode, nije:

![Cutter prikazuje različite rezultate analize kada se isti bajtovi otvore kao datoteka ili kao shellcode](<../../images/image (562).png>)

Da biste pokrenuli emulaciju na željenom mestu, tamo postavite bp i Cutter će, po svemu sudeći, automatski pokrenuti emulaciju odatle:

![Postavljanje breakpoint-a na željenu ulaznu tačku shellcode-a pre pokretanja Cutter emulacije](<../../images/image (589).png>)

![Cutter emulator pauziran na izabranoj shellcode tački prekida](<../../images/image (387).png>)

Na primer, stek možete videti unutar hex dump-a:

![Prikaz steka emuliranog shellcode-a u Cutter-ovom hex dump-u](<../../images/image (186).png>)

### Uklanjanje obfuskacije shellcode-a i pronalaženje funkcija koje se izvršavaju

Isprobajte [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Pokazaće vam, na primer, **koje funkcije** shellcode koristi i da li se shellcode **dekodira** u memoriji.

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

Opcija **Create Dump** izbacuje konačni shellcode ako je došlo do bilo kakve dinamičke promene shellcode-a u memoriji (korisno za preuzimanje dekodiranog shellcode-a). Opcija **start offset** može biti korisna za pokretanje shellcode-a od određenog pomeraja. Opcija **Debug Shell** korisna je za debagovanje shellcode-a pomoću scDbg terminala (međutim, smatram da je bilo koja od prethodno objašnjenih opcija bolja za to, jer ćete moći da koristite Ida ili x64dbg).

### Disasembliranje pomoću CyberChef-a

Otpremite datoteku sa shellcode-om kao ulaz i upotrebite sledeći recept da biste ga dekompilirali: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskacija MBA obfuskacije

**Mixed Boolean-Arithmetic (MBA)** obfuskacija skriva jednostavne izraze kao što je `x + y` iza formula koje kombinuju aritmetičke operatore (`+`, `-`, `*`) i bitovske operatore (`&`, `|`, `^`, `~`, pomeranja). Važno je da su ovi identiteti obično tačni samo u okviru **modularne aritmetike fiksne širine**, pa su prenosi i prekoračenja bitni:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ako ovaj tip izraza pojednostavite pomoću generičkih algebarskih alata, lako možete dobiti pogrešan rezultat jer semantika širine bita nije uzeta u obzir.<sup>[[1]](#references)</sup>

### Praktični postupak

1. **Sačuvajte originalnu širinu bita** iz lifted koda/IR/decompiler izlaza (`8/16/32/64` bita).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
   - **Linearni**: ponderisani zbirovi bitovskih atoma
   - **Semilinearni**: linearni izraz plus konstantne maske kao što je `x & 0xFF`
   - **Polinomski**: prisutni su proizvodi
   - **Mešoviti**: proizvodi i bitovska logika su isprepletani, često uz ponovljene podizraze
3. **Proverite svako predloženo prepisivanje** nasumičnim testiranjem ili SMT dokazom. Ako ekvivalencija ne može da se dokaže, zadržite originalni izraz umesto da nagađate.

### Zaobiđite spljošteni kontrolni tok pomoću uskog izvršnog isečka

Često nije neophodno rekonstruisati kompletan graf kontrolnog toka. Kod spljoštavanja kontrolnog toka, opaque predicates, velikih dispečera ili koda sa mnogo MBA operacija, pratite reference od šifrovanih blokova i izlaznih bafera do najmanje rutine koja ih transformiše. Zatim reprodukujte samo taj isečak toka podataka ili ga izvršite nezavisno; dispečer nije deo potrebnog rešenja ako se relevantno stanje može direktno inicijalizovati.<sup>[[7]](#references)</sup>

Praktični postupak je:<sup>[[7]](#references)</sup>

1. Popišite izvršne i podatkovne sekcije, relokacije i unakrsne reference. Izbacite kandidatske tabele iz `.rodata`, čuvajući redosled bajtova i širinu elemenata.
2. Identifikujte poslednju rutinu koja upisuje plaintext ili izlazni bafer. Zabeležite njene ulaze, referencirane tabele, uvezene pozive i potrebno globalno stanje.
3. Prenesite samo te operacije u Python model fiksne širine. Ako isečak i dalje zavisi od previše stanja, pozovite rutinu pomoću Unicorn, QEMU ili debagera i zakačite nevažne uvezene funkcije umesto da emuliрате ceo program.
4. Potvrdite da extractor zaista izvodi svoj izlaz iz dostavljene binarne datoteke: uklonite tihe rezervne opcije, pretražite je u potrazi za ugrađenim odgovorima i pokrenite ga nad nepoznatim buildovima sa izmenjenim stringovima, ključevima, identifikatorima, rasporedima i seedovima za obfuskaciju.

Korisne komande za prvi prolaz su:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Otkrivanje MBA izraza koji prikrivaju konstante

Naizgled izraz za bajt koji zavisi od ulaza može potpuno da poništi svoj ulaz. Nakon izdvajanja tabela, izračunajte izraz za ceo 8-bitni domen; skup izlaza koji sadrži samo jednu vrednost dokazuje da je taj bajt konstanta, bez potrebe za rekonstrukcijom okolne mašine stanja.<sup>[[7]](#references)</sup>

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

Zadržite završnu masku jer se pri originalnom sabiranju vrednosti prelivaju na širini bajta. Za širi domen, pitajte SMT solver da li je izraz `f(x1) != f(x2)` zadovoljiv za dva simbolička ulaza iste širine: `unsat` dokazuje invarijantnost, dok `sat` daje kontraprimer i znači da se ulaz ne može odbaciti.<sup>[[7]](#references)</sup>

#### Prepoznajte dekodiranje vezano za okruženje

Provere protiv analize ne moraju da granaju tok izvršavanja niti da izazovu pad. Dekoder može da uključi rezultat senzora u bit ključa, konstantu opaque predicate-a ili stanje spljoštenog dispečera, da nastavi normalno i u emulatoru proizvede uverljiv, ali netačan otvoreni tekst. Zato nije dovoljno zakrpiti samo vidljive grane koje izazivaju grešku; pratite zavisnosti podataka od provera okruženja do stanja dekodera, uporedite isti segment na autentičnom uređaju i emulatoru i proverite kako forsiranje svakog rezultata senzora menja završni bafer.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktičan MBA simplifier za analizu malvera i reverzni inženjering zaštićenih binarnih fajlova. Klasifikuje izraz i usmerava ga kroz specijalizovane obrade, umesto da na sve primenjuje jedan generički prolaz za prepisivanje.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA izračunava izraz na Booleovim ulazima, izvodi potpis i istovremeno pokreće nekoliko metoda za oporavak, kao što su uparivanje obrazaca, konverzija u ANF i interpolacija koeficijenata.
- **Semilinear MBA**: atomi maskirani konstantama ponovo se izgrađuju rekonstrukcijom podeljenom po bitovima, tako da maskirani regioni ostanu ispravni.
- **Polynomial/Mixed MBA**: proizvodi se rastavljaju na jezgra, a ponovljeni podizrazi mogu se izdvojiti u privremene promenljive pre pojednostavljivanja spoljne relacije.

Primer mešovitog identiteta koji često vredi pokušati oporaviti:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Ovo se može svesti na:

```c
x * y
```

### Beleške o reverznom inženjerstvu

- Prednost dajte pokretanju CoBRA nad **lifted IR expressions** ili izlazom dekompilatora nakon što izolujete tačan proračun.
- Eksplicitno koristite `--bitwidth` kada je izraz nastao iz masked arithmetic ili uskih registara.
- Ako vam je potreban snažniji korak dokazivanja, pogledajte lokalne Z3 beleške ovde:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA dolazi i kao **LLVM pass plugin** (`libCobraPass.so`), što je korisno kada želite da normalizujete MBA-heavy LLVM IR pre kasnijih analiza.
- Nepodržane carry-sensitive mixed-domain residuals treba smatrati signalom da zadržite originalni izraz i ručno analizirate putanju prenosa.

## Oporavak XOR-state control-flow flattening-a

OLLVM-style flattener može da čuva stanje trenutnog basic block-a u dva 64-bitna registra i da ga rekonstruiše pomoću XOR-a u dispatcher-u. Svaki originalni blok upisuje par za svoje sledeće stanje i skače nazad u dispatcher. Uslovni blok može da koristi `CMOVcc` da zameni jednu polovinu para u skladu sa CPU flag-ovima, pa praćenjem samo vidljivih branch instrukcija možete propustiti dva nasledna bloka. Za razliku od dispatcher-a sa indirect jump-om, ovaj oblik može svuda da koristi direktne povratne skokove.<sup>[[19]](#references)[[20]](#references)</sup>

Da biste rekonstruisali graf, pronađite stablo poređenja dispatcher-a i dva registra stanja, mapirajte svako poređeno XOR stanje na ciljni blok, a zatim pratite upise u par registara koji dolaze do svakog originalnog bloka. Kod uslovnih upisa uključite instrukciju koja postavlja flag-ove i oba ishoda `CMOVcc` instrukcije. Izlaz dispatcher-a svakog bloka zamenite odgovarajućim direktnim naslednim blokom ili uslovnim grananjem; dispatcher tada postaje nedostižan bez izmene binarnog fajla. Ovo je pristup sa celim CFG-om; ako je važan samo jedan decoder, [narrow execution-slice workflow](#bypass-flattened-control-flow-with-a-narrow-execution-slice) iznad može biti brži.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatizuje ovaj oblik u Binary Ninja. Kopirajte `plugins/DispatchThis` u korisnički direktorijum za Binary Ninja plugin-ove i ponovo pokrenite program. Na funkciji na koju se ovo odnosi otvorite **Function Settings** i izaberite `OLLVM_XOR_64`; ako analiza ne počne, upotrebite **Analysis → Reanalyze All Functions**. Ovaj režim prepisuje MLIL control-flow ivice, a ne bajtove fajla, i ne zahteva Z3 ni indirect-jump resolver. Testiran je na Binary Ninja 5.3.9757+; ne uklanja neaktivne upise stanja po blokovima, pa ih nemojte pomešati sa preostalim aktivnim prelazima.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuscator zamenjuje operacije programa nizovima instrukcija zasnovanim na `mov` i koristi obradu signala/izuzetaka za izmenu control flow-a. Detalji:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Za podržane binarne fajlove, [demovfuscator](https://github.com/kirschju/demovfuscator) može da deobfuscate rezultat. Ima nekoliko zavisnosti.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

I [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako igrate **CTF, ovo zaobilazno rešenje za pronalaženje zastavice** može biti veoma korisno: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **ulaznu tačku**, pretražite funkcije po `::main`, kao u primeru:

![Pronalaženje ulazne tačke Rust programa u Ghidra-i pretragom naziva funkcija za dvotačku-dvotačku main](<../../images/image (1080).png>)

U ovom slučaju, binarna datoteka se zvala authenticator, pa je prilično očigledno da je ovo zanimljiva main funkcija.\
Kada saznate **nazive** pozvanih **funkcija**, potražite ih na **Internetu** da biste saznali više o njihovim **ulazima** i **izlazima**.

### Oporavak Rust stringova iz ELF firmware-a

U **Rust ELF** binarnim datotekama, mnogi statički stringovi nisu referencirani kao pokazivači sa NUL terminatorom u C stilu. Uobičajeni raspored koji koristi `rustc` jeste **torka pokazivača i dužine** unutar **`.data.rel.ro`**, koja pokazuje na stvarni string blob smešten u **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

To znači da `strings` ili podrazumevana analiza u Ghidri mogu spojiti susedne stringove ili u potpunosti propustiti unakrsne reference.<sup>[[3]](#references)</sup>

Brz tok rada:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pronađite virtuelnu adresu i veličinu sekcije **`.rodata`**.
2. Prođite kroz **`.data.rel.ro`** reč po reč.
3. Svaku vrednost unutar opsega adresa `.rodata` tretirajte kao mogući pokazivač na string.
4. Sledeću reč tretirajte kao moguću dužinu.
5. Primenenite filtere za proveru ispravnosti (na primer, zadržite dužine između **4** i **100** bajtova).
6. Pročitajte tačno `length` bajtova iz `.rodata` umesto da skenirate do `0x00`.

Minimalna logika ekstraktora:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Ovo je naročito korisno pri firmware reversing-u, jer pronađeni Rust stringovi često otkrivaju **HTTP rute, RPC nazive, log poruke, provere, nazive datoteka, konfiguracione ključeve, obrađivače komandi i logiku povezanu sa autentifikacijom**.

Ako Ghidra ne pronađe te stringove, pokrenite prilagođenu skriptu/plugin koja primenjuje istu heuristiku i kreira podatke stringova na referenciranim `.rodata` pomerajima. Objavljeni alati `rust-strings` i `RustStrings.py` kompanije Pen Test Partners korisni su kao reference za prilagođavanje ove ideje drugim **veličinama reči, redosledima bajtova i rasporedima sekcija**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Za binarne datoteke kompajlirane za Delphi možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako treba da radite reverse engineering Delphi binarne datoteke, predlažem da koristite IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pritisnite **Alt+F7** u IDA-i da biste učitali Python plugin, a zatim izaberite datoteku plugina.

Ovaj plugin će pokrenuti binarnu datoteku i dinamički razrešiti nazive funkcija na početku debugging-a. Kada pokrenete debugging, ponovo pritisnite dugme Start (zeleno dugme ili f9) i breakpoint će se aktivirati na početku pravog koda.

Ako pritisnete dugme u grafičkoj aplikaciji, debugger može da se zaustavi u funkciji koju je to dugme pozvalo.

## Golang

Za uobičajene Go binarne datoteke, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) može da povrati runtime strukture i poboljša nazive funkcija u IDA-i. Učitajte njegov Python plugin pomoću **Alt+F7**.

Ako treba da radite reverse engineering Golang binarne datoteke, predlažem da koristite IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pritisnite **Alt+F7** u IDA-i da biste učitali Python plugin, a zatim izaberite datoteku plugina.

Ovim će se razrešiti nazivi funkcija.

### Oporavljanje metapodataka bez tabele simbola

I dalje su potrebni runtime metapodaci da bi se u skraćenom Go izvršnom fajlu povezali programski brojači sa funkcijama. [GoReSym](https://github.com/mandiant/GoReSym) pronalazi i parsira strukture kao što su `pclntab` i `moduledata`, koristeći kod izveden iz Go runtime-a. Tako se mogu oporaviti granice funkcija, nazivi, izvorne putanje, tipovi i detalji o izgradnji bez oslanjanja na uobičajenu tabelu simbola.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuskator može da ostavi te strukture upotrebljivim, a da pritom zameni rekonstruisana imena. Garble, na primer, hešira identifikatore i putanje paketa i uklanja informacije o build-u, modulu i debagovanju.<sup>[[12]](#references)</sup> Obfuskirani token paketa mora da bude dosledan kroz funkcije iz tog paketa. Grupisati funkcije prema ponovljenom tokenu, zaključiti o kom je paketu reč na osnovu njegovih poziva, stringova i API-ja, a zatim tu oznaku paketa dodeliti celoj grupi.<sup>[[13]](#references)</sup>

### Rekonstrukcija Garble imena pomoću GoResolver-a

[GoResolver](https://github.com/volexity/GoResolver) objedinjuje izdvajanje runtime simbola, generisanje čistih referenci i uparivanje grafova toka kontrole (CFG). Koristite sledeći redosled:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifikujte verziju kompajlera.** Najpre proverite `BuildInfo` i ugrađene stringove verzije. Ako ih je obfuskator uklonio, uporedite delove priloženog Go runtime-a sa referentnim runtime-ovima za određene verzije. U Volexity testovima, oko `2%` runtime-a bilo je dovoljno da se razlikuju glavne verzije Go-a. Tretirajte ovo kao empirijsku optimizaciju, a ne univerzalni prag.<sup>[[13]](#references)</sup>
2. **Pripremite odgovarajuće reference.** Generišite čiste binarne fajlove za utvrđenu verziju Go-a, ciljnu arhitekturu i verovatne biblioteke. Usklađivanje toolchain-a smanjuje razlike u CFG-u koje je uneo kompajler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Uporedite funkcije.** GoGrapher uparuje CFG-ove funkcija i daje normalizovane ocene od `0.0` do `1.0`. Njegovo uparivanje osnovnih blokova zasniva se na ponderisanom poređenju sličnih instrukcija. Uparivanja sa visokim stepenom pouzdanosti mapiraju nasumično imenovane funkcije na čistu implementaciju. Slabija uparivanja i dalje mogu da identifikuju paket ili modul.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Proverite i uvezite.** Potvrdite predložena imena pomoću odnosa poziva, konstanti, stringova i sporednih efekata, a zatim uvezite JSON izveštaj pomoću GoResolver dodatka za IDA ili Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instalirajte toolchain i pokrenite objedinjeni ekstraktor i uparivač grafova:<sup>[[10]](#references)</sup>

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

Podrazumevani prag značajnog poklapanja je `0.9`. Prekidači `--extract` i `--graph` mogu da izdvoje bilo koju fazu, dok se podrazumevano pokreću obe jer se oporavljeni runtime metapodaci i dokazi iz CFG-a međusobno dopunjuju.<sup>[[10]](#references)</sup> CFG ocene su heurističke: inlining, build zastavice, arhitektura i razlike u verzijama biblioteka mogu da promene oblik grafa, zato sačuvajte funkcije čiji nazivi nisu razrešeni umesto da im dodeljujete nazive sa niskim nivoom pouzdanosti.<sup>[[13]](#references)</sup>

### Oporavak Go tabele stringova

Go binarni fajlovi smeštaju bajtove stringova iz svih povezanih paketa u jednu neprekidnu tabelu. Unosi nisu završeni NUL bajtom, a runtime strukture ne otkrivaju početnu adresu ni veličinu tabele. Međutim, kompajler raspoređuje unose prvo po dužini, a zatim po abecednom redu, nezavisno od operativnog sistema i arhitekture. Zato analitičar, nakon što pronađe jedan unos, može da prođe kroz susedne unose i pomoću unakrsnih referenci podataka poveže stringove sa kodom.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatizuje ovaj postupak u IDA Pro i Ghidra. Najpre sačekajte da se završi automatska analiza jer se dodatak oslanja na unakrsne reference u segmentu podataka. Podrazumevano koristi runtime string `entersyscall` kao sidro, a zatim može da pretražuje u oba smera, definiše oporavljene stringove u bazi i izveze JSON mapiranje stringova i funkcija koje ih referenciraju.<sup>[[14]](#references)</sup>

Filtrirajte izveštaj prema paketu funkcije koja referencira string da biste razdvojili kod aplikacije ili malware-a od šuma koji potiče od povezanih biblioteka. Ovom tehnikom ne mogu da se oporave literali uništeni obfuskacijom, kao što je Garble-ova transformacija `-literals`. I dalje može da pomogne u organizovanju runtime stringova koji nisu obfuscirani.<sup>[[14]](#references)[[15]](#references)</sup>

### Oporavak Go runtime tipova

Go ugrađuje informacije o runtime tipovima koje koriste funkcije kao što je garbage collection. Kada se uklone build informacije ili disassembler ne parsira ove metapodatke, može izgledati kao da instrukcije učitavaju proizvoljne adrese podataka, a ciljna oblast ostaje netipizovana. Oporavak metapodataka pretvara te adrese u čitljive reference na tipove i olakšava razumevanje mogućnosti paketa.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) može da izdvoji simbole i parsira runtime tipove u JSON izveštaj. Trenutni CLI koristi podkomandu `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Opcija `-y`/`--types` omogućava parsiranje tipova. Uvezite izveštaj pomoću GoResolver dodatka za IDA Pro ili Ghidra da biste definisali oporavljene tipove i primenili njihove reference u bazi podataka za analizu. U formatu izveštaja uvedenom ovom funkcijom, ako izostavite `-y`, članovi RTTI address i recovered-types ostaju null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver podržava PE, ELF i Mach-O uzorke za x86, AMD64, ARM i ARM64, pa isti postupak važi za Go binarne datoteke iz Windowsa, Linuxa i macOS-a.<sup>[[10]](#references)</sup>

## Kompajlirani Python

Na ovoj stranici možete pronaći uputstva za izdvajanje Python koda iz kompajlirane Python binarne datoteke ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ako dobijete **binarnu datoteku** GBA igre, možete koristiti različite alate da biste je **emulirali** i **otklanjali greške**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite verziju za otklanjanje grešaka_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra dodatak
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra dodatak

U programu [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_** ** možete videti kako se pritiskaju **dugmad** na Game Boy Advance konzoli

![Konfiguracija kontrola za no$gba koja prikazuje mapiranje dugmadi za Game Boy Advance](<../../images/image (581).png>)

Kada se pritisne, svaki **taster ima vrednost** po kojoj se identifikuje:

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

U toj funkciji, nakon nekoliko inicijalizacionih operacija (koje nisu važne):

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

Poslednji if proverava da li je **`uVar4`** među poslednjim Keys i da li nije trenutni taster, što znači da je taster otpušten (trenutni taster se čuva u **`uVar1`**).

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

U prethodnom kodu možete videti da poredimo **uVar1** (mesto na kojem se nalazi **vrednost pritisnutog dugmeta**) sa nekim vrednostima:

- Prvo se poredi sa **vrednošću 4** (dugme **SELECT**): U challenge-u ovo dugme briše ekran
- Zatim se vrednost poredi sa **8** (dugme **START**); u ovom challenge-u, ta grana proverava da li je uneti kod validan.
  - U tom slučaju, promenljiva **`DAT_030000d8`** poredi se sa 0xf3 i, ako su vrednosti iste, izvršava se određeni kod.
- U svim ostalim slučajevima proverava se i uvećava brojač (`DAT_030000d4`).\
  Dok je brojač manji od 8, vrednosti pritisnutih tastera sabiraju se u `DAT_030000d8`.

Dakle, u ovom challenge-u, znajući vrednosti dugmadi, trebalo je da **pritisnete kombinaciju kraću od 8 dugmadi čiji zbir iznosi 0xf3.**

**Referenca za ovaj tutorijal:** [arhivirani Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [6] [Nostalgia - GBA reverse engineering tutorijal (arhivirano)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Pobeda nad reverse engineering-om uz pomoć AI-ja, ili bar pokušaj](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Pristup poređenju grafova toka kontrole zasnovan na uparivanju osnovnih blokova](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repozitorijum](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble mehanizam obfuskacije](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Korišćenje sličnosti grafova toka kontrole za automatsku deobfuskaciju Golang binarnih fajlova](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repozitorijum](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Novosti o Volexity Golang alatima](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [REA analiza upravljanog koda](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI i vodič za dokaze](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Tok rada za uklanjanje izravnavanja toka kontrole u Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: Upad putem zero-day ranjivosti PaperCut MF, Java loader, web shell i AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
{{#include ../../banners/hacktricks-training.md}}
