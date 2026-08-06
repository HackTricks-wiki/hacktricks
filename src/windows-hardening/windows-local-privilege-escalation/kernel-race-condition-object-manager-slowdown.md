# Eksploatacija Kernel Race Condition putem sporih putanja Object Manager-a

{{#include ../../banners/hacktricks-training.md}}

## Zašto je važno produžiti race window

Mnogi Windows kernel LPE-ovi prate klasičan obrazac `check_state(); NtOpenX("name"); privileged_action();`. Na modernom hardveru, cold `NtOpenEvent`/`NtOpenSection` razrešava kratko ime za približno 2 µs, ostavljajući gotovo nimalo vremena da se provereno stanje promeni pre izvršavanja secure action-a. Namernim primoravanjem Object Manager Namespace (OMNS) lookup-a u koraku 2 da traje desetine mikrosekundi, attacker dobija dovoljno vremena da dosledno dobije inače nepouzdane race uslove bez potrebe za hiljadama pokušaja.<sup>[[1]](#references)</sup>

## Ukratko o internim detaljima Object Manager lookup-a

* **OMNS struktura** – Imena kao što je `\BaseNamedObjects\Foo` razrešavaju se directory po directory. Svaka komponenta zahteva da kernel pronađe/otvori *Object Directory* i uporedi Unicode stringove. Symbolic links (npr. slova diskova) mogu se pratiti tokom ovog procesa.
* **UNICODE_STRING ograničenje** – OM putanje se prenose unutar `UNICODE_STRING` čiji je `Length` 16-bitna vrednost. Apsolutno ograničenje iznosi 65 535 bajtova (32 767 UTF-16 codepoint-ova). Sa prefiksima poput `\BaseNamedObjects\`, attacker i dalje kontroliše približno 32 000 karaktera.
* **Preduslovi za attacker-a** – Svaki user može da kreira objekte unutar writable direktorijuma kao što je `\BaseNamedObjects`. Kada vulnerable code koristi ime unutar takvog direktorijuma ili prati symbolic link koji tamo vodi, attacker kontroliše performanse lookup-a bez posebnih privilegija.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Jedna maksimalna komponenta

Trošak razrešavanja komponente približno je linearan u odnosu na njenu dužinu, jer kernel mora da izvrši Unicode poređenje sa svakim unosom u parent direktorijumu. Kreiranje event-a sa imenom dugim 32 kB odmah povećava `NtOpenEvent` latency sa približno 2 µs na približno 35 µs na Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktične napomene*

- Ograničenje dužine možete dostići pomoću bilo kog imenovanog kernel objekta (events, sections, semaphores…).
- Symbolic links ili reparse points mogu usmeravati kratko ime „victim“ ka ovoj ogromnoj komponenti, tako da se slowdown primenjuje transparentno.
- Pošto se sve nalazi u namespace-ovima koje korisnik može da menja, payload funkcioniše sa standardnim user integrity level-om.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Duboko rekurzivni direktorijumi

Agresivnija varijanta alocira lanac od hiljada direktorijuma (`\BaseNamedObjects\A\A\...\X`). Svaki korak aktivira logiku za razrešavanje direktorijuma (provere ACL-a, hash lookups, reference counting), pa je latencija po nivou veća nego kod jednog poređenja stringova. Sa približno 16.000 nivoa (ograničeno istom veličinom `UNICODE_STRING` strukture), empirijska merenja premašuju prag od 35 µs postignut pomoću dugih pojedinačnih komponenti.
```cpp
ScopedHandle base_dir = OpenDirectory(L"\\BaseNamedObjects");
HANDLE last_dir = base_dir.get();
std::vector<ScopedHandle> dirs;
for (int i = 0; i < 16000; i++) {
dirs.emplace_back(CreateDirectory(L"A", last_dir));
last_dir = dirs.back().get();
if ((i % 500) == 0) {
auto result = RunTest(GetName(last_dir) + L"\\X", iterations);
printf("%d,%f\n", i + 1, result);
}
}
```
Saveti:

* Menjajte karakter po nivou (`A/B/C/...`) ako nadređeni direktorijum počne da odbija duplikate.
* Čuvajte niz handle-ova kako biste mogli uredno da obrišete lanac nakon exploitation-a i izbegnete zagađivanje namespace-a.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minuti umesto mikrosekundi)

Object direktorijumi podržavaju **shadow directories** (fallback lookups) i hash tabele podeljene na bucket-e za entries. Zloupotrebite oba mehanizma, zajedno sa ograničenjem od 64 komponente za symbolic-link reparse, kako biste višestruko povećali usporavanje bez prekoračenja dužine `UNICODE_STRING`:

1. Kreirajte dva direktorijuma unutar `\BaseNamedObjects`, na primer `A` (shadow) i `A\A` (target). Kreirajte drugi koristeći prvi kao shadow directory (`NtCreateDirectoryObjectEx`), tako da se missing lookups u `A` prosleđuju na `A\A`.
2. Popunite svaki direktorijum hiljadama **colliding names** koje završavaju u istom hash bucket-u (na primer, menjajte završne cifre dok zadržavate istu `RtlHashUnicodeString` vrednost). Lookups sada prelaze u O(n) linearna skeniranja unutar jednog direktorijuma.
3. Izgradite lanac od približno 63 **object manager symbolic links** koji se ponovo parsiraju u dugački `A\A\…` suffix i troše reparse budžet. Svaki reparse ponovo pokreće parsiranje od početka, višestruko povećavajući collision cost.
4. Lookup finalne komponente (`...\\0`) sada traje **minutima** na Windows 11 kada je u svakom direktorijumu prisutno 16 000 collisions, što praktično garantuje dobijanje race-a kod one-shot kernel LPE-ova.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Zašto je važno*: Usporavanje od nekoliko minuta pretvara jednokratne LPE zasnovane na race uslovima u determinističke exploite.<sup>[[1]](#references)</sup>

### Beleške o ponovnom testiranju iz 2025. i gotovi alati

- James Forshaw je ponovo objavio tehniku sa ažuriranim vremenskim vrednostima na Windows 11 24H2 (ARM64). Osnovna otvaranja i dalje traju približno 2 µs; komponenta od 32 kB povećava to na približno 35 µs, dok shadow-dir + collision + lanci sa 63 reparse nivoa i dalje dostižu približno 3 minuta, čime se potvrđuje da primitives opstaju u aktuelnim buildovima. Izvorni kod i perf harness nalaze se u osveženoj Project Zero objavi.<sup>[[1]](#references)</sup>
- Podešavanje možete skriptovati pomoću javno dostupnog paketa `symboliclink-testing-tools`: `CreateObjectDirectory.exe` za kreiranje para shadow/target i `NativeSymlink.exe` u petlji za generisanje lanca od 63 hop-a. Ovo izbegava ručno pisanje `NtCreate*` wrappera i održava ACL-ove doslednim.<sup>[[2]](#references)</sup>

## Merenje vašeg race prozora

Ugradite brzi harness u svoj exploit da biste izmerili koliko veliki prozor postaje na hardveru žrtve. Ispod navedeni snippet otvara ciljni objekat `iterations` puta i vraća prosečnu cenu po otvaranju koristeći `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
```cpp
static double RunTest(const std::wstring name, int iterations,
std::wstring create_name = L"", HANDLE root = nullptr) {
if (create_name.empty()) {
create_name = name;
}
ScopedHandle event_handle = CreateEvent(create_name, root);
ObjectAttributes obja(name);
std::vector<ScopedHandle> handles;
Timer timer;
for (int i = 0; i < iterations; ++i) {
HANDLE open_handle;
Check(NtOpenEvent(&open_handle, MAXIMUM_ALLOWED, &obja));
handles.emplace_back(open_handle);
}
return timer.GetTime(iterations);
}
```
Rezultati direktno utiču na vašu strategiju orkestracije race-a (npr. broj potrebnih worker thread-ova, intervale spavanja i koliko rano treba da promenite deljeno stanje).

## Tok eksploatacije

1. **Locirajte ranjivi open** – Pratite putanju kernela (kroz simbole, ETW, hypervisor tracing ili reversing) dok ne pronađete poziv `NtOpen*`/`ObOpenObjectByName` koji obrađuje ime pod kontrolom napadača ili symbolic link u direktorijumu u koji korisnik može da upisuje.
2. **Zamenite to ime sporom putanjom**
- Kreirajte dugu komponentu ili lanac direktorijuma pod `\BaseNamedObjects` (ili drugim OM root-om u koji može da se upisuje).
- Kreirajte symbolic link tako da se ime koje kernel očekuje sada razrešava na sporu putanju. Vulnerable driver-ov directory lookup možete usmeriti na svoju strukturu bez menjanja originalnog target-a.
3. **Pokrenite race**
- Thread A (victim) izvršava ranjivi kod i blokira se unutar sporog lookup-a.
- Thread B (attacker) menja zaštićeno stanje (npr. zamenjuje file handle, ponovo upisuje symbolic link ili menja object security) dok je Thread A zauzet.
- Kada Thread A nastavi izvršavanje i obavi privileged action, uočava zastarelo stanje i izvršava operaciju pod kontrolom napadača.
4. **Očistite za sobom** – Obrišite lanac direktorijuma i symbolic links da ne biste ostavili sumnjive artefakte ili prekinuli rad legitimnih IPC korisnika.<sup>[[1]](#references)</sup>

## Operativna razmatranja

- **Kombinujte primitive** – Možete koristiti dugo ime *po nivou* u lancu direktorijuma za još veću latenciju, sve dok ne iscrpite veličinu `UNICODE_STRING`.
- **One-shot bugs** – Prošireni prozor (od desetina mikrosekundi do nekoliko minuta) čini “single trigger” bugs realističnim kada se kombinuju sa CPU affinity pinning-om ili preemption-om uz pomoć hypervisor-a.
- **Sporedni efekti** – Usporavanje utiče samo na malicious path, tako da ukupne performanse sistema ostaju nepromenjene; defenders će to retko primetiti osim ako nadziru rast namespace-a.
- **Čišćenje** – Zadržite handles ka svakom direktorijumu/objektu koji kreirate kako biste nakon toga mogli da pozovete `NtMakeTemporaryObject`/`NtClose`. Inače neograničeni lanci direktorijuma mogu ostati prisutni i nakon reboot-a.
- **File-system races** – Ako se ranjiva putanja na kraju razrešava kroz NTFS, možete postaviti Oplock (npr. `SetOpLock.exe` iz istog toolkit-a) na backing file dok OM slowdown traje, zamrzavajući consumer na dodatnih nekoliko milisekundi bez izmene OM graph-a.<sup>[[2]](#references)</sup>

## Odbrambene napomene

- Kernel kod koji se oslanja na named objects treba ponovo da validira security-sensitive stanje *nakon* open-a ili da uzme reference pre provere (čime se zatvara TOCTOU praznina).
- Uvedite gornje granice za dubinu/dužinu OM putanje pre dereferenciranja imena pod kontrolom korisnika. Odbacivanje predugačkih imena prisiljava napadače da se vrate u mikrosekundni prozor.
- Instrumentujte rast namespace-a Object Manager-a (ETW `Microsoft-Windows-Kernel-Object`) kako biste otkrili sumnjive lance sa hiljadama komponenti pod `\BaseNamedObjects`.

## Reference

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
