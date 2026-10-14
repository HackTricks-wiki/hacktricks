# Alati za reversing i osnovne metode

{{#include ../../banners/hacktricks-training.md}}

## Alati za reversing zasnovani na ImGui

Softver:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automatizacija WinDbg-a u korisničkom režimu

{{#ref}}
windbg-automation.md
{{#endref}}

## Otklanjanje grešaka u Windows kernelu

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm dekompilator / Wat kompajler

Na mreži:

- Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) za **dekompilaciju** wasm-a (binarni format) u wat (čitljiv tekst)
- Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) za **kompilaciju** wat-a u wasm
- Za dekompilaciju možete isprobati i [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

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

## .NET dekompilator

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je dekompilator koji **dekompilira i pregleda više formata**, uključujući **biblioteke** (.dll), **datoteke Windows metapodataka** (.winmd) i **izvršne datoteke** (.exe). Kada se sklop dekompilira, može da se sačuva kao Visual Studio projekat (.csproj).

Prednost je u tome što, ako je potrebno obnoviti izgubljeni izvorni kod iz starog sklopa, ovaj postupak može da uštedi vreme. Pored toga, dotPeek omogućava praktično kretanje kroz dekompilirani kod, pa je jedan od savršenih alata za **analizu Xamarin algoritama.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Zahvaljujući sveobuhvatnom modelu dodataka i API-ju koji omogućava prilagođavanje alata vašim konkretnim potrebama, .NET Reflector štedi vreme i pojednostavljuje razvoj. Pogledajmo mnoštvo usluga za reverse engineering koje ovaj alat pruža:

- Omogućava uvid u to kako podaci prolaze kroz biblioteku ili komponentu
- Omogućava uvid u implementaciju i upotrebu .NET jezika i okvira
- Pronalazi nedokumentirane i nedostupne funkcionalnosti kako biste bolje iskoristili korišćene API-je i tehnologije.
- Pronalazi zavisnosti i različite sklopove
- Otkriva tačnu lokaciju grešaka u vašem kodu, komponentama trećih strana i bibliotekama.
- Omogućava otklanjanje grešaka u izvornom kodu celokupnog .NET koda s kojim radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) i [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy dodatak za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga koristiti na bilo kom OS-u (možete ga instalirati direktno iz VSCode-a, bez potrebe da preuzimate git. Kliknite na **Extensions** i **potražite ILSpy**).\
Ako želite da **dekompilirate**, **izmenite** i ponovo **kompilirate**, možete koristiti [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ili njegov aktivno održavani fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Desni klik -> Modify Method** da biste nešto promenili unutar funkcije).

### Pregled upravljanog koda bez izvršavanja pomoću REA

**REA** može da pregleda PE/CLI metapodatke i CIL bez učitavanja sklopa. Počnite od identiteta artefakta, a zatim pregledajte članove i deklarisane izvorne granice; ovo je korisno pri proveri sumnjivih poziva pre upotrebe dekompilatora ili pokretanja programa.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Za poređenje verzija, `compare_managed_members` koristi sirovi identitet CIL-a/potpisa i otiske dekodiranih instrukcija, umesto da tretira tokene metapodataka kao stabilne između izgradnji. P/Invoke deklaracija nije dokaz da je native code pokrenut; `verify_managed_native_boundaries` zahteva podudaran native export ili dokaz funkcije da bi proverio tu granicu. Uz rezultat sačuvajte digest artefakta, MVID i nerazrešena mapiranja.<sup>[[17]](#references)</sup>

### DNSpy logovanje

Da bi **DNSpy zabeležio neke informacije u datoteci**, možete upotrebiti ovaj isečak:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Da biste debugovali kod pomoću DNSpy-ja, potrebno je da:

Najpre promenite **atribute sklopa** povezane sa **debugovanjem**:

![DNSpy Logging - DNSpy Debugging: Najpre promenite atribute sklopa povezane sa debugovanjem](<../../images/image (973).png>)

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

Ovo je neophodno jer će se, ako to ne uradite, pri **runtime**-u na kod primeniti nekoliko **optimizacija**, pa je moguće da tokom otklanjanja grešaka **prelomna tačka nikada ne bude dostignuta** ili da **neke promenljive ne postoje**.

Zatim, ako vašu .NET aplikaciju **pokreće** **IIS**, možete je **ponovo pokrenuti** pomoću:

```
iisreset /noforce
```

Zatim, da biste započeli debugovanje, zatvorite sve otvorene datoteke, pa na kartici **Debug** izaberite **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Zatim, da biste započeli debugovanje, zatvorite sve otvorene datoteke, pa na kartici Debug izaberite Attach to Process](<../../images/image (318).png>)

Zatim izaberite **w3wp.exe** da biste se povezali sa **IIS serverom** i kliknite na **attach**:

![DNSpy Logging - DNSpy Debugging: Zatim izaberite w3wp.exe da biste se povezali sa IIS serverom i kliknite na attach](<../../images/image (113).png>)

Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Najpre kliknite na _Debug >> Break All_, a zatim na _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Najpre kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sada kada debugujemo proces, vreme je da ga zaustavimo i učitamo sve module. Najpre kliknite na Debug Break All, a zatim na Debug Windows Modules](<../../images/image (834).png>)

Kliknite na bilo koji modul u odeljku **Modules** i izaberite **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknite na bilo koji modul u odeljku Modules i izaberite Open All Modules](<../../images/image (922).png>)

Kliknite desnim tasterom miša na bilo koji modul u **Assembly Explorer** i izaberite **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknite desnim tasterom miša na bilo koji modul u Assembly Explorer i izaberite Sort Assemblies](<../../images/image (339).png>)

## Java dekompajler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugovanje DLL-ova

### Korišćenje IDA-e

- **Učitajte rundll32** (64-bitnu verziju iz C:\Windows\System32\rundll32.exe, a 32-bitnu iz C:\Windows\SysWOW64\rundll32.exe)
- Izaberite debugger **Windbg**
- Izaberite "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Izaberite " Suspend on library load/unload "](<../../images/image (868).png>)

- Podesite **parametre** izvršavanja tako što ćete navesti **putanju do DLL-a** i funkciju koju želite da pozovete:

![Debugging DLLs - Using IDA: Podesite parametre izvršavanja tako što ćete navesti putanju do DLL-a i funkciju koju želite da pozovete](<../../images/image (704).png>)

Zatim, kada započnete debugovanje, **izvršavanje će se zaustaviti pri učitavanju svake DLL biblioteke**. Dakle, kada rundll32 učita vašu DLL biblioteku, izvršavanje će se zaustaviti.

Ovaj metod zaustavlja izvršavanje pri događajima učitavanja modula, ali dolazak do ulazne tačke učitane DLL biblioteke nije toliko direktan kao u x64dbg postupku opisanom u nastavku.

### Korišćenje x64dbg/x32dbg

- **Učitajte rundll32** (64-bitnu verziju iz C:\Windows\System32\rundll32.exe, a 32-bitnu iz C:\Windows\SysWOW64\rundll32.exe)
- **Promenite komandnu liniju** ( _File --> Change Command Line_ ) i unesite putanju do DLL-a i funkciju koju želite da pozovete, na primer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Promenite _Options --> Settings_ i izaberite "**DLL Entry**".
- Zatim **pokrenite izvršavanje**. Debugger će se zaustaviti na svakoj funkciji dll main, a u nekom trenutku će se **zaustaviti na ulaznoj tački vaše DLL biblioteke**. Odatle samo potražite mesta na koja želite da postavite breakpoint.

Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg, možete da vidite **u kom ste kodu** tako što ćete pogledati **vrh prozora win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Imajte na umu da, kada se izvršavanje iz bilo kog razloga zaustavi u win64dbg, možete da vidite u kom ste kodu tako što ćete pogledati vrh prozora win64dbg](<../../images/image (842).png>)

Ovaj indikator potvrđuje da je izvršavanje zaustavljeno unutar DLL biblioteke koju želite da debugujete.

## GUI aplikacije / video-igre

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje važnih vrednosti sačuvanih u memoriji pokrenute igre i njihovu izmenu. Više informacija:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) je front-end/alati za reverse engineering za GNU Project Debugger (GDB), usmeren na igre. Međutim, može da se koristi za bilo kakve zadatke povezane sa reverse engineeringom.

[**Decompiler Explorer**](https://dogbolt.org/) je web front-end za više dekompajlera. Ova web usluga omogućava poređenje izlaza različitih dekompajlera za male izvršne datoteke.

## Istraga nativnog koda potkrepljena dokazima uz REA

**REA** omogućava pristup analizama iz Hopper-a, Ghidra-e i IDA-e putem CLI-ja i MCP-ja. Potrebni su Node.js 22.x (najmanje 22.19), 24.x (najmanje 24.11) ili 26+, kao i npm. Najpre konfigurišite postojeći nativni provider; proverite `rea providers --json` i izaberite provider eksplicitno ako ih više podržava cilj. U nastavku zamenite `0x1000` opaženim imenom funkcije ili adresom iz inventara.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Počni od feature string-a ili simbola, prati reference i pozivaoce, a zatim pregledaj dosije izabrane funkcije i pseudokod pomoću `rea decompile`. REA vezuje sesiju za izabranog provajdera, umesto da ga neprimetno zameni nakon greške. Za ponovljive upite, `--snapshot PATH` ponovo koristi samo bajtove artefakta, provajdera, podešavanja, operaciju i parametre koji se poklapaju; snapshot je lokalni keš, a ne sačuvana baza podataka provajdera. Sačuvaj vraćeni Evidence i eksplicitno navedene nepoznanice, umesto da izvedene putanje ili tekst dekompilatora tretiraš kao originalni izvorni kod.<sup>[[16]](#references)[[18]](#references)</sup>

Za JavaScript/Electron ulazne tačke koje vode do native add-on-ova, pogledaj [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging shellcode-a pomoću blobrunner-a

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alocira **shellcode**, ispisuje njegovu **memorijsku adresu** i pauzira izvršavanje.\
Prikači debugger, kao što su IDA ili x64dbg, postavi breakpoint na ispisanu adresu i nastavi izvršavanje da bi debugovao shellcode.

Na GitHub stranici sa izdanjima nalaze se ZIP arhive sa kompajliranim izdanjima: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blago izmenjenu verziju Blobrunner-a možeš pronaći na sledećem linku. Da bi je kompajlirao, samo **napravi C/C++ projekat u Visual Studio Code-u, kopiraj i nalepi kod i izgradi ga**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging shellcode-a pomoću jmp2it-a

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) je sličan BlobRunner-u. Alocira shellcode i ulazi u beskonačnu petlju. Prikači debugger, nastavi izvršavanje na **2–5 sekundi**, pauziraj unutar petlje i izvršavaj instrukciju po instrukciju do sledećeg poziva koji prenosi izvršavanje na alocirani shellcode.

![Debugger pauziran u beskonačnoj petlji jmp2it-a, neposredno pre poziva alociranog shellcode-a](<../../images/image (509).png>)

Kompajliranu verziju [jmp2it-a možeš preuzeti na stranici sa izdanjima](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode-a pomoću Cutter-a

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je GUI za radare. Pomoću Cutter-a možeš emulirati shellcode i dinamički ga pregledati.

Imaj na umu da Cutter omogućava opcije „Open File“ i „Open Shellcode“. U mom slučaju, kada sam otvorio shellcode kao datoteku, dekompilacija je bila ispravna, ali kada sam ga otvorio kao shellcode, nije:

![Cutter prikazuje različite rezultate analize pri otvaranju istih bajtova kao datoteke ili kao shellcode-a](<../../images/image (562).png>)

Da bi emulacija počela na željenom mestu, postavi breakpoint tamo; izgleda da će Cutter automatski pokrenuti emulaciju od te tačke:

![Postavljanje breakpoint-a na željeni ulaz shellcode-a pre pokretanja emulacije u Cutter-u](<../../images/image (589).png>)

![Emulator u Cutter-u pauziran na izabranom breakpoint-u shellcode-a](<../../images/image (387).png>)

Možeš, na primer, da vidiš stek unutar hex dump-a:

![Prikaz steka emuliranog shellcode-a u hex dump-u Cutter-a](<../../images/image (186).png>)

### Deobfuscating shellcode-a i pronalaženje izvršenih funkcija

Probaj [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Reći će ti stvari kao što su **koje funkcije** shellcode koristi i da li se **dekodira** u memoriji.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg takođe ima grafički pokretač u kom možete da izaberete željene opcije i izvršite shellcode

![Grafički pokretač scDbg za izbor opcija emulacije i praćenja shellcode-a](<../../images/image (258).png>)

Opcija **Create Dump** izbacuje završni shellcode ako je tokom rada došlo do bilo kakve dinamičke izmene shellcode-a u memoriji (korisno za preuzimanje dekodiranog shellcode-a). Opcija **start offset** može biti korisna za pokretanje shellcode-a od određenog pomeraja. Opcija **Debug Shell** korisna je za otklanjanje grešaka u shellcode-u pomoću scDbg terminala (međutim, za ovu namenu smatram da je bilo koja od prethodno objašnjenih opcija bolja, jer ćete moći da koristite Ida ili x64dbg).

### Disasembliranje pomoću CyberChef-a

Otpremite shellcode datoteku kao ulaz i upotrebite sledeći recept da biste je disasemblirali: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation skriva jednostavne izraze kao što je `x + y` iza formula koje kombinuju aritmetičke operatore (`+`, `-`, `*`) i bitovne operatore (`&`, `|`, `^`, `~`, pomeranja). Važno je da su ovi identiteti obično tačni samo u okviru **aritmetike po modulu fiksne širine**, pa su prenosi i prekoračenja bitni:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ako pojednostavite ovakav izraz pomoću generičkih alata za algebru, lako možete dobiti pogrešan rezultat jer semantika širine bitova nije uzeta u obzir.<sup>[[1]](#references)</sup>

### Praktični postupak

1. **Sačuvajte originalnu širinu bitova** iz lifted koda/IR izlaza/dekompilatora (`8/16/32/64` bita).
2. **Klasifikujte izraz** pre nego što pokušate da ga pojednostavite:
   - **Linearni**: ponderisani zbirovi bitovskih atoma
   - **Semilinearni**: linearni izrazi sa konstantnim maskama kao što je `x & 0xFF`
   - **Polinomski**: sadrže proizvode
   - **Mešoviti**: proizvodi i bitovska logika su isprepletani, često sa ponovljenim podizrazima
3. **Proverite svako predloženo prepisivanje** nasumičnim testiranjem ili SMT dokazom. Ako se ekvivalencija ne može dokazati, zadržite originalni izraz umesto da nagađate.

### Zaobiđite spljošteni tok kontrole pomoću uskog izvršnog isečka

Rekonstrukcija kompletnog grafa toka kontrole često nije potrebna. Kod spljoštavanja toka kontrole, neprozirnih predikata, velikih dispečera ili koda sa mnogo MBA operacija, pratite reference od šifrovanih blobova i izlaznih bafera do najmanje rutine koja ih transformiše. Zatim reprodukujte samo taj isečak toka podataka ili ga izvršite nezavisno; dispečer nije deo potrebnog rešenja ako se relevantno stanje može direktno inicijalizovati.<sup>[[7]](#references)</sup>

Praktični postupak je:<sup>[[7]](#references)</sup>

1. Popišite izvršne i podatkovne sekcije, relokacije i unakrsne reference. Izdvojite potencijalne tabele iz `.rodata`, uz očuvanje redosleda bajtova i širine elemenata.
2. Pronađite poslednju rutinu koja upisuje otvoreni tekst ili izlazni bafer. Zabeležite njene ulaze, referencirane tabele, uvezene pozive i potrebno globalno stanje.
3. Prenesite samo te operacije u Python model fiksne širine. Ako taj isečak i dalje zavisi od previše stanja, pozovite rutinu pomoću alata Unicorn, QEMU ili debagera i presretните nebitne uvezene funkcije umesto da emuliрате ceo program.
4. Proverite da ekstraktor zaista izvodi svoj izlaz iz dostavljenog binarnog fajla: uklonite neprimetne rezervne opcije, pretražite ga u potrazi za ugrađenim odgovorima i testirajte ga na neviđenim verzijama sa izmenjenim stringovima, ključevima, identifikatorima, rasporedima i seedovima za obfuskaciju.

Korisne komande za početnu proveru su:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Otkrivanje MBA izraza koji su prikrivene konstante

Naizgled od ulaza zavisan izraz nad bajtom može potpuno da poništi svoj ulaz. Nakon izdvajanja tabela, izračunajte izraz nad celim 8-bitnim domenom; skup izlaza sa jednim elementom dokazuje da je taj bajt konstanta, bez potrebe za rekonstrukcijom okolne mašine stanja.<sup>[[7]](#references)</sup>

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

#### Prepoznavanje dekodiranja vezanog za okruženje

Provere protiv analize ne moraju da granaju tok izvršavanja niti da izazovu pad. Dekoder može da umeša rezultat senzora u bit ključa, konstantu opaque-predicate-a ili stanje flattened-dispatcher-a, da nastavi normalno i proizvede uverljiv, ali netačan plaintext u emulatoru. Zato nije dovoljno zakrpiti samo vidljive grane koje dovode do neuspeha; pratite zavisnosti podataka od proba okruženja do stanja dekodera, uporedite isti segment na autentičnom uređaju i u emulatoru i proverite kako forsiranje svakog rezultata senzora menja završni bafer.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) je praktičan MBA simplifier za analizu malware-a i reverse engineering zaštićenih binarnih datoteka. Klasifikuje izraz i usmerava ga kroz specijalizovane pipeline-ove, umesto da na sve primenjuje jedan generički prolaz za prepisivanje.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evaluira izraz nad Bulovim ulazima, izvodi potpis i paralelno pokreće nekoliko metoda oporavka, kao što su uparivanje obrazaca, ANF konverzija i interpolacija koeficijenata.
- **Semilinear MBA**: atomi maskirani konstantama obnavljaju se rekonstrukcijom podelom na bitove, tako da maskirani regioni ostanu ispravni.
- **Polynomial/Mixed MBA**: proizvodi se razlažu na jezgra, a ponavljajući podizrazi mogu se izdvojiti u privremene promenljive pre pojednostavljivanja spoljne relacije.

Primer mešovitog identiteta koji često vredi pokušati oporaviti:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Ovo se može svesti na:

```c
x * y
```

### Napomene o reverse engineeringu

- Prednost dajte pokretanju CoBRA nad **podignutim IR izrazima** ili izlazom dekompilatora nakon što izdvojite tačno izračunavanje.
- Koristite `--bitwidth` eksplicitno kada izraz potiče od aritmetike sa maskama ili uskih registara.
- Ako vam je potreban jači korak dokazivanja, pogledajte lokalne Z3 beleške ovde:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA se isporučuje i kao **LLVM pass plugin** (`libCobraPass.so`), što je korisno kada želite da normalizujete LLVM IR sa mnogo MBA operacija pre narednih faza analize.
- Nepodržane rezidue mešovitog domena osetljive na prenos treba tretirati kao znak da zadržite originalni izraz i ručno analizirate putanju prenosa.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuscator zamenjuje programske operacije nizovima instrukcija zasnovanim na `mov` instrukciji i koristi obradu signala/izuzetaka da bi promenio tok kontrole. Detalji:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Za podržane binarne fajlove, [demovfuscator](https://github.com/kirschju/demovfuscator) može da deobfuskuje rezultat. Ima nekoliko zavisnosti.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

I [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako igrate **CTF, ovo zaobilazno rešenje za pronalaženje zastavice** može biti veoma korisno: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Da biste pronašli **entry point**, pretražite funkcije po `::main`, kao ovde:

![Pronalaženje Rust entry point-a u Ghidra-i pretraživanjem naziva funkcija po dvostrukoj dvotački i main](<../../images/image (1080).png>)

U ovom slučaju, binarna datoteka se zvala authenticator, pa je prilično očigledno da je ovo zanimljiva main funkcija.\
Kada saznate **nazive** pozvanih **funkcija**, pretražite ih na **Internetu** da biste saznali više o njihovim **ulazima** i **izlazima**.

### Oporavak Rust stringova iz ELF firmvera

U **Rust ELF** binarnim datotekama, mnogi statički stringovi nisu referencirani kao pokazivači sa završnim NUL znakom u C stilu. Uobičajen raspored u `rustc`-u je **torka pokazivač/dužina** unutar **`.data.rel.ro`**, koja pokazuje na stvarni blok stringova smešten u **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

To znači da `strings` ili podrazumevana analiza u Ghidra-i mogu spojiti susedne stringove ili potpuno propustiti unakrsne reference.<sup>[[3]](#references)</sup>

Brzi tok rada:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pronađite virtuelnu adresu i veličinu sekcije **`.rodata`**.
2. Enumerišite sekciju **`.data.rel.ro`** reč po reč.
3. Svaku vrednost unutar opsega adresa sekcije `.rodata` tretirajte kao mogući pokazivač na string.
4. Sledeću reč tretirajte kao moguću dužinu.
5. Primeniite provere smislenosti (na primer, zadržite dužine između **4** i **100** bajtova).
6. Iz sekcije `.rodata` pročitajte tačno `length` bajtova umesto da tražite sve do `0x00`.

Minimalna logika ekstraktora:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Ovo je naročito korisno pri reverznom inženjerstvu firmware-a, jer oporavljeni Rust stringovi često otkrivaju **HTTP rute, RPC nazive, poruke u logovima, provere, nazive fajlova, konfiguracione ključeve, rukovaoce komandama i logiku povezanu sa autentifikacijom**.

Ako Ghidra ne pronađe te stringove, pokrenite prilagođenu skriptu/dodatak koji primenjuje istu heuristiku i kreira string podatke na referenciranim `.rodata` pomerajima. Objavljeni alati `rust-strings` i `RustStrings.py` kompanije Pen Test Partners dobre su reference za prilagođavanje ove ideje drugim **veličinama reči, redosledima bajtova i rasporedima sekcija**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Za binarne fajlove kompajlirane za Delphi možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako treba da izvršite reverzno inženjerstvo Delphi binarnog fajla, predlažem da koristite IDA dodatak [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pritisnite **Alt+F7** u IDA-i da biste učitali Python dodatak, a zatim izaberite fajl dodatka.

Ovaj dodatak će pokrenuti binarni fajl i dinamički razrešiti nazive funkcija na početku otklanjanja grešaka. Nakon pokretanja otklanjanja grešaka, ponovo pritisnite dugme Start (zeleno dugme ili f9) i breakpoint će se aktivirati na početku stvarnog koda.

Ako pritisnete dugme u grafičkoj aplikaciji, debugger može da se zaustavi u funkciji koju to dugme poziva.

## Golang

Za uobičajene Go binarne fajlove, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) može da oporavi runtime strukture i poboljša nazive funkcija u IDA-i. Učitajte njegov Python dodatak pomoću **Alt+F7**.

Ako treba da izvršite reverzno inženjerstvo Golang binarnog fajla, predlažem da koristite IDA dodatak [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pritisnite **Alt+F7** u IDA-i da biste učitali Python dodatak, a zatim izaberite fajl dodatka.

Ovo će razrešiti nazive funkcija.

### Oporavak metapodataka bez tabele simbola

I dalje je potrebna runtime metapodatkovna struktura u stripped Go izvršnoj datoteci da bi se programski brojači povezali sa funkcijama. [GoReSym](https://github.com/mandiant/GoReSym) pronalazi i parsira strukture kao što su `pclntab` i `moduledata`, koristeći kod izveden iz Go runtime-a. Time se mogu oporaviti granice funkcija, nazivi, izvorne putanje, tipovi i detalji o izgradnji bez oslanjanja na uobičajenu tabelu simbola.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuskator može da ostavi te strukture upotrebljivim, a da zameni oporavljena imena. Na primer, Garble hešira identifikatore i putanje paketa i uklanja informacije o build-u, modulima i debugovanju.<sup>[[12]](#references)</sup> Obfuskirani token paketa mora da ostane dosledan u funkcijama iz tog paketa. Grupisanje funkcija prema ponovljenom tokenu, zaključivanje o jednom paketu na osnovu njegovih poziva, stringova i API-ja, a zatim prenošenje te oznake paketa na celu grupu.<sup>[[13]](#references)</sup>

### Oporavak imena koje je Garble izmenio pomoću GoResolver-a

[GoResolver](https://github.com/volexity/GoResolver) objedinjuje izdvajanje runtime simbola, generisanje čistih referenci i poklapanje grafova toka kontrole (CFG). Koristite sledeći redosled:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifikujte verziju kompajlera.** Najpre pokušajte sa `BuildInfo` i ugrađenim nizovima verzija. Ako ih je obfuskator uklonio, uporedite delove priloženog Go runtime-a sa referentnim runtime-ovima za pojedinačne verzije. U Volexity testovima, oko `2%` runtime-a bilo je dovoljno da se razlikuju glavne verzije Go-a. Smatrajte ovo empirijskom optimizacijom, a ne univerzalnim pragom.<sup>[[13]](#references)</sup>
2. **Pripremite odgovarajuće reference.** Generišite čiste binarne datoteke za identifikovanu verziju Go-a, ciljnu arhitekturu i verovatne biblioteke. Usklađivanje lanca alata smanjuje razlike u CFG-u koje stvara kompajler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Uporedite funkcije.** GoGrapher upoređuje CFG-ove funkcija i daje normalizovane rezultate od `0.0` do `1.0`. Njegovo upoređivanje osnovnih blokova zasniva se na ponderisanom poređenju sličnih instrukcija. Poklapanja sa visokim stepenom pouzdanosti povezuju nasumično preimenovane funkcije sa čistom implementacijom. Slabija poklapanja i dalje mogu da identifikuju paket ili modul.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Proverite i uvezite.** Potvrdite predložena imena pomoću veza između poziva, konstanti, stringova i sporednih efekata, a zatim uvezite JSON izveštaj pomoću GoResolver dodatka za IDA ili Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instalirajte lanac alata i pokrenite objedinjeni ekstraktor i alat za poklapanje grafova:<sup>[[10]](#references)</sup>

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

Podrazumevani prag značajnog poklapanja je `0.9`. Opcije `--extract` i `--graph` mogu zasebno da pokrenu bilo koju fazu, dok se podrazumevano pokreću obe jer se oporavljeni runtime metapodaci i dokazi iz CFG-a međusobno dopunjuju.<sup>[[10]](#references)</sup> CFG ocene su heurističke: inlining, build zastavice, arhitektura i razlike u verzijama biblioteka mogu da promene oblik grafa, zato zadržite nerazrešene funkcije umesto da im dodeljujete imena sa malim stepenom pouzdanosti.<sup>[[13]](#references)</sup>

### Oporavak Go tabele stringova

Go binarne datoteke smeštaju bajtove stringova iz svih povezanih paketa u jednu neprekidnu tabelu. Unosi se ne završavaju nul-terminatorom, a runtime strukture ne otkrivaju početnu adresu ni veličinu tabele. Međutim, kompajler na svim operativnim sistemima i arhitekturama prvo sortira unose po dužini, a zatim abecedno. Zato analitičar, nakon što pronađe jedan unos, može da prolazi kroz susedne unose i da pomoću unakrsnih referenci podataka poveže stringove sa kodom.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatizuje ovaj postupak u IDA Pro i Ghidra. Sačekajte da se završi automatska analiza jer se dodatak oslanja na unakrsne reference segmenata podataka. Kao podrazumevanu početnu tačku koristi runtime string `entersyscall`, nakon čega može da pretražuje u oba smera, definiše oporavljene stringove u bazi podataka i izveze JSON mapiranje stringova na funkcije koje ih referenciraju.<sup>[[14]](#references)</sup>

Filtrirajte izveštaj prema paketu funkcije koja referencira string da biste razdvojili kod aplikacije ili malvera od šuma povezanih biblioteka. Ovom tehnikom ne mogu da se oporave literali uklonjeni obfuskacijom, kao što je Garble-ova transformacija `-literals`. Ipak, njome se mogu organizovati runtime stringovi koji su ostali neobfuskirani.<sup>[[14]](#references)[[15]](#references)</sup>

### Oporavak Go runtime tipova

Go ugrađuje informacije o runtime tipovima koje koriste funkcije kao što je garbage collection. Kada se uklone informacije o build-u ili disassembler ne obradi ove metapodatke, instrukcije mogu izgledati kao da učitavaju proizvoljne adrese podataka, a ciljna oblast ostaje bez tipa. Oporavak metapodataka pretvara te adrese u čitljive reference na tipove i olakšava razumevanje mogućnosti paketa.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) može da izdvoji simbole i obradi runtime tipove u JSON izveštaj. Trenutni CLI koristi potkomandu `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Opcija `-y`/`--types` omogućava parsiranje tipova. Uvezite izveštaj pomoću IDA Pro ili Ghidra dodatka za GoResolver da biste definisali oporavljene tipove i primenili njihove reference u bazi podataka analize. U formatu izveštaja uvedenom ovom funkcijom, izostavljanje opcije `-y` ostavlja članove RTTI adrese i oporavljenih tipova kao null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver podržava uzorke PE, ELF i Mach-O za x86, AMD64, ARM i ARM64, tako da se isti postupak može primeniti na Go binarne fajlove iz Windows-a, Linux-a i macOS-a.<sup>[[10]](#references)</sup>

## Kompajlirani Python

Na ovoj stranici možete pronaći kako da dobijete Python kod iz ELF/EXE binarnog fajla kompajliranog iz Python-a:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ako nabavite **binary** neke GBA igre, možete koristiti različite alate da biste je **emulirali** i **debugovali**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite debug verziju_) - Sadrži debugger sa interfejsom
- [**mgba** ](https://mgba.io)- Sadrži CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra dodatak
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra dodatak

U [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_** ** možete videti kako se pritiskaju **dugmad** Game Boy Advance konzole

![no$gba konfiguracija kontrola koja prikazuje mapiranje dugmadi Game Boy Advance konzole](<../../images/image (581).png>)

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

Dakle, u ovakvom programu zanimljiv deo biće **način na koji program obrađuje korisnički unos**. Na adresi **0x4000130** pronaći ćete često korišćenu funkciju: **KEYINPUT**.

![Ghidra prikaz GBA binarne datoteke koja upućuje na KEYINPUT na adresi 0x4000130](<../../images/image (447).png>)

Na prethodnoj slici možete videti da se funkcija poziva iz **FUN_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekoliko init operacija (koje nisu bitne):

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

Poslednji if proverava da li se **uVar4** nalazi u prethodnim Keys i da li nije trenutni taster, što se naziva i otpuštanjem dugmeta (trenutni taster je sačuvan u **uVar1**).

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

U prethodnom kodu možete da vidite da poredimo **uVar1** (mesto gde se nalazi **vrednost pritisnutog dugmeta**) sa nekim vrednostima:

- Prvo se poredi sa **vrednošću 4** (dugme **SELECT**): u izazovu ovo dugme briše ekran
- Zatim se poredi sa **8** (dugme **START**); u ovom izazovu, ta putanja proverava da li je uneti kod ispravan.
  - U ovom slučaju, varijabla **`DAT_030000d8`** poredi se sa 0xf3 i ako su vrednosti jednake, izvršava se određeni kod.
- U svim ostalim slučajevima proverava se brojač (`DAT_030000d4`) i uvećava se.\
  Dok je brojač manji od 8, vrednosti pritisnutih tastera sabiraju se u `DAT_030000d8`.

Dakle, u ovom izazovu, pošto znate vrednosti dugmadi, trebalo je da **pritisnete kombinaciju kraću od 8 dugmadi čiji zbir iznosi 0xf3.**

**Referenca za ovaj tutorijal:** [arhivirani vodič za izazov Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursevi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (deobfuskacija binarnih fajlova)

## References

- [1] [Pojednostavljivanje MBA obfuskacije pomoću CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repozitorijum](https://github.com/trailofbits/CoBRA)
- [3] [Dekodiranje Rust stringova - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA vodič za reverse engineering (arhivirano)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Pobeda nad AI-potpomognutim reverse engineeringom, ili bar pokušaj](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Pristup poređenju grafova toka kontrole zasnovan na uparivanju osnovnih blokova](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repozitorijum](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mehanizam obfuskacije Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Korišćenje sličnosti grafova toka kontrole za automatsku deobfuskaciju Golang binarnih fajlova](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repozitorijum](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Novosti o Volexity Golang alatima](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [REA analiza upravljanog koda](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI i vodič za dokaze](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
