# Eksploatacija kernel Race Condition-a preko sporih puteva Object Manager-a

{{#include ../../banners/hacktricks-training.md}}

## Zašto produženje race window-a ima značaja

Mnogi Windows kernel LPEs prate klasičan obrazac `check_state(); NtOpenX("name"); privileged_action();`. Na modernom hardveru, hladan `NtOpenEvent`/`NtOpenSection` rešava kratko ime za ~2 µs, ostavljajući skoro nimalo vremena da se promeni provereno stanje pre nego što se izvrši bezbedna akcija. Namernim forsiranjem Object Manager Namespace (OMNS) lookup-a u koraku 2 da traje desetine mikrosekundi, napadač dobija dovoljno vremena da dosledno pobedi inače nestabilne race-ove bez potrebe za hiljadama pokušaja.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Imena poput `\BaseNamedObjects\Foo` rešavaju se direktorijum-po-direktorijum. Svaka komponenta tera kernel da pronađe/otvori *Object Directory* i uporedi Unicode stringove. Simbolične veze (npr. oznake drajvova) mogu biti prolazno pređene.
* **UNICODE_STRING limit** – OM putevi su nošeni unutar `UNICODE_STRING` čija je `Length` 16-bitna vrednost. Apsolutna granica je 65 535 bajtova (32 767 UTF-16 kodnih tačaka). Sa prefiksima poput `\BaseNamedObjects\`, napadač i dalje kontroliše ≈32 000 karaktera.
* **Attacker prerequisites** – Bilo koji korisnik može kreirati objekte unutar writable direktorijuma kao što je `\BaseNamedObjects`. Kada ranjiv kod koristi ime unutra, ili sledi simboličku vezu koja završi tamo, napadač kontroliše performanse lookup-a bez posebnih privilegija.

## Slowdown primitive #1 – Single maximal component

Trošak rešavanja jedne komponente je otprilike linearan u odnosu na njenu dužinu zato što kernel mora da izvrši Unicode poređenje sa svakim unosom u parent direktorijumu. Kreiranjem event-a sa imenom dugo 32 kB odmah se povećava latencija `NtOpenEvent` sa ~2 µs na ~35 µs na Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktične napomene*

- Možete pogoditi ograničenje dužine koristeći bilo koji imenovani kernel object (events, sections, semaphores…).
- Symbolic links or reparse points mogu usmeriti kratko “victim” ime na ovaj giant component tako da se usporavanje primenjuje transparentno.
- Pošto sve živi u user-writable namespaces, payload radi sa standardnim user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Agresivnija varijanta alocira lanac od hiljada direktorijuma (`\BaseNamedObjects\A\A\...\X`). Svaki skok pokreće logiku rezolucije direktorijuma (ACL checks, hash lookups, reference counting), pa je latencija po nivou veća nego kod pojedinačnog poređenja stringova. Sa ~16 000 nivoa (ograničeno istom `UNICODE_STRING` veličinom), empirijska merenja premašuju granicu od 35 µs postignutu dugim pojedinačnim komponentama.
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

* Naizmenično menjajte karakter po nivou (`A/B/C/...`) ako roditeljski direktorijum počne da odbija duplikate.
* Držite niz handle-ova tako da možete čisto obrisati lanac nakon exploitacije kako biste izbegli zagađivanje namespace-a.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minuta umesto mikrosekundi)

Object directories podržavaju **shadow directories** (fallback lookups) i bucketed hash tables za unose. Iskoristite oba plus limit od 64 komponenta za symbolic-link reparse da umnožite usporavanje bez prekoračenja dužine `UNICODE_STRING`:

1. Kreirajte dva direktorijuma pod `\BaseNamedObjects`, npr. `A` (shadow) i `A\A` (target). Kreirajte drugi koristeći prvi kao shadow directory (`NtCreateDirectoryObjectEx`), tako da se nedostajuće pretrage u `A` prosleđuju u `A\A`.
2. Popunite svaki direktorijum sa hiljadama **colliding names** koje se nalaze u istom hash bucket-u (npr. menjajući završne cifre dok održavate istu vrednost `RtlHashUnicodeString`). Pretrage sada degradiraju na O(n) linearne skenove unutar jednog direktorijuma.
3. Sastavite lanac od ~63 **object manager symbolic links** koji se ponovo reparse-uju u dugi sufiks `A\A\…`, trošeći reparse budžet. Svaki reparse ponovo pokreće parsiranje od početka, umnožavajući cenu kolizije.
4. Pretraga poslednje komponente (`...\\0`) sada traje **minuta** na Windows 11 kada je prisutno 16 000 kolizija po direktorijumu, obezbeđujući praktično zagarantovanu pobedu u race-uslovu za one-shot kernel LPE-e.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Zašto je važno*: Višeminutno usporavanje pretvara one-shot race-based LPEs u deterministic exploits.

## Merenje vašeg race window-a

Umetnite kratak harness u svoj exploit da izmerite koliko velik postane race window na hardveru žrtve. Primer ispod otvara ciljni objekat `iterations` puta i vraća prosečan trošak po otvaranju koristeći `QueryPerformanceCounter`.
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
Rezultati direktno utiču na vašu strategiju orkestracije race condition-a (npr. broj radnih niti koje su potrebne, intervali spavanja, koliko rano treba promeniti zajedničko stanje).

## Tok eksploatacije

1. **Pronađite ranjivi poziv open** – Pratite kernel stazu (preko simbola, ETW, hypervisor tracing, ili reversing) dok ne nađete poziv `NtOpen*`/`ObOpenObjectByName` koji prolazi kroz ime kontrolisano od napadača ili simbolički link u direktorijumu u koji korisnik može pisati.
2. **Zamenite to ime sporim putem**
- Kreirajte dugačku komponentu ili lanac direktorijuma pod `\BaseNamedObjects` (ili drugim zapisivim OM root-om).
- Kreirajte simbolički link tako da ime koje kernel očekuje sada rezolvira na spori put. Možete usmeriti pretragu direktorijuma ranjivog drajvera na vašu strukturu bez diraња originalne mete.
3. **Pokrenite trku (race)**
- Nit A (žrtva) izvršava ranjivi kod i blokira se unutar sporog lookup-a.
- Nit B (napadač) menja zaštićeno stanje (npr. zamenjuje file handle, prepisuje simbolički link, menja object security) dok je Nit A zauzeta.
- Kada se Nit A nastavi i izvrši privilegovanu akciju, ona vidi zastarelo stanje i izvršava operaciju koju kontroliše napadač.
4. **Čišćenje** – Obrišite lanac direktorijuma i simboličke linkove kako ne biste ostavili sumnjive artefakte ili pokvarili legitimne IPC korisnike.

## Operativna razmatranja

- **Kombinujte primitivе** – Možete koristiti dugo ime po nivou u lancu direktorijuma za još veće kašnjenje dok ne dostignete veličinu `UNICODE_STRING`.
- **Jednokratne ranjivosti** – Prošireni vremenski prozor (desetine mikrosekundi do minuta) čini „single trigger“ ranjivosti realistično kad se upari sa podešavanjem CPU afiniteta ili preempicijom podržanom od hypervisora.
- **Neblagovremeni efekti** – Uspon performansi utiče samo na maliciozni put, tako da ukupne performanse sistema ostaju neoštećene; branitelji to retko primete osim ako ne prate rast namespace-a.
- **Čišćenje** – Zadržite handle-e za svaki direktorijum/objekat koji kreirate tako da možete pozvati `NtMakeTemporaryObject`/`NtClose` naknadno. U suprotnom, neograničeni lanci direktorijuma mogu opstati i preko reboota.

## Napomene za odbranu

- Kernel kod koji zavisi od imenovanih objekata treba da ponovo validira sigurnosno osetljivo stanje *nakon* open-a, ili da uzme referencu pre provere (zatvarajući TOCTOU rupu).
- Nametnite gornje granice na dubinu/dužinu OM putanje pre dereferenciranja imena koje kontroliše korisnik. Odbacivanje predugih imena primoraće napadače nazad u mikrosekundni prozor.
- Instrumentujte rast object manager namespace-a (ETW `Microsoft-Windows-Kernel-Object`) da detektujete sumnjive lance sa hiljadama komponenti pod `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
