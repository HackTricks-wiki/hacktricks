# Eksploatacija kernel race uslova putem sporih puteva Object Manager-a

{{#include ../../banners/hacktricks-training.md}}

## Zašto je važno produžiti race prozor

Mnogi Windows kernel LPEs slede klasični obrazac `check_state(); NtOpenX("name"); privileged_action();`. Na modernom hardveru hladan `NtOpenEvent`/`NtOpenSection` razreši kratak naziv za ~2 µs, ostavljajući gotovo nikakvo vreme da se promeni prethodno provereno stanje pre nego što se izvrši sigurna akcija. Namernim forsiranjem lookup-a Object Manager Namespace (OMNS) u koraku 2 da traje desetine mikrosekundi, napadač dobija dovoljno vremena da dosledno pobedi inače nepouzdane race-ove bez potrebe za hiljadama pokušaja.

## Interna pretraga Object Manager-a ukratko

* **OMNS struktura** – Nazivi poput `\BaseNamedObjects\Foo` se razrešavaju direktorijum-po-direktorijum. Svaka komponenta tera kernel da pronađe/otvori *Object Directory* i uporedi Unicode stringove. Symbolic links (npr. slova drajva) se mogu pratiti usput.
* **UNICODE_STRING limit** – OM putanje se nose unutar `UNICODE_STRING` čije je `Length` 16-bitna vrednost. Apsolutni limit je 65 535 bajtova (32 767 UTF-16 codepoint-a). Sa prefiksima kao `\BaseNamedObjects\`, napadač i dalje kontroliše ≈32 000 karaktera.
* **Zahtevi za napadača** – Bilo koji korisnik može kreirati objekte ispod upisivih direktorijuma kao što je `\BaseNamedObjects`. Kada ranjiv kod koristi naziv unutar tog direktorijuma, ili sledi symbolic link koji tamo vodi, napadač kontroliše performanse lookup-a bez posebnih privilegija.

## Primitiv za usporavanje #1 – Jedna maksimalna komponenta

Trošak razrešavanja jedne komponente je približno linearan u odnosu na njenu dužinu jer kernel mora izvršiti Unicode poređenje protiv svakog unosa u roditeljskom direktorijumu. Kreiranje event-a sa imenom dugim 32 kB odmah povećava latenciju `NtOpenEvent` sa ~2 µs na ~35 µs na Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktične napomene*

- Možete dostići ograničenje dužine koristeći bilo koji imenovani kernel objekat (events, sections, semaphores…).
- Symbolic links ili reparse points mogu preusmeriti kratko “victim” ime na ovu ogromnu komponentu tako da se usporavanje primeni transparentno.
- Pošto sve živi u user-writable namespaces, payload radi sa standardnim user integrity level-om.

## Slowdown primitive #2 – Deep recursive directories

Agresivnija varijanta alocira lanac od nekoliko hiljada direktorijuma (`\BaseNamedObjects\A\A\...\X`). Svaki skok pokreće logiku rešavanja direktorijuma (ACL checks, hash lookups, reference counting), pa je latencija po nivou veća od prostog poređenja stringa. Sa ~16 000 nivoa (ograničeno istom `UNICODE_STRING` veličinom), empirijski merenja prevazilaze barijeru od 35 µs koju postižu duge pojedinačne komponente.
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
* Držite handle array tako da možete uredno obrisati lanac nakon eksploatacije i izbeći zagađivanje namespace-a.

## Merenje vašeg race window-a

Ugradite kratak harness u svoj exploit da izmerite koliko veliki prozor postaje na hardveru žrtve. Primer ispod otvara ciljani objekat `iterations` puta i vraća prosečan trošak po otvaranju koristeći `QueryPerformanceCounter`.
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
Rezultati se direktno ugrađuju u vašu strategiju orkestracije race-a (npr. broj radnih niti koje su potrebne, intervali čekanja, koliko rano treba promeniti deljeno stanje).

## Exploitation workflow

1. **Locate the vulnerable open** – Pratite kernel putanju (preko symbols, ETW, hypervisor tracing, ili reversing) dok ne pronađete poziv `NtOpen*`/`ObOpenObjectByName` koji pretražuje ime pod kontrolom napadača ili simbolički link u direktorijumu koji je zapisiv od strane korisnika.
2. **Replace that name with a slow path**
- Kreirajte dugačku komponentu ili lanac direktorijuma pod `\BaseNamedObjects` (ili drugim zapisivim OM root-om).
- Napravite simbolički link tako da ime koje kernel očekuje sada pokazuje na slow path. Možete usmeriti pretragu direktorijuma ranjivog drajvera na vašu strukturu bez diranja originalne mete.
3. **Trigger the race**
- Thread A (žrtva) izvršava ranjivi kod i blokira se unutar slow lookup-a.
- Thread B (napadač) menja čuvano stanje (npr. zamenjuje file handle, prepisuje simbolički link, menja object security) dok je Thread A zauzet.
- Kada se Thread A nastavi i izvrši privilegovanu akciju, vidi zastarelo stanje i izvršava operaciju pod kontrolom napadača.
4. **Clean up** – Obrišite lanac direktorijuma i simboličke linkove kako biste izbegli ostavljanje sumnjivih artefakata ili prekid legitimnih IPC korisnika.

## Operational considerations

- **Combine primitives** – Možete koristiti dugo ime *po nivou* u lancu direktorijuma za još veću latenciju sve dok ne iscrpite veličinu `UNICODE_STRING`.
- **One-shot bugs** – Prošireni prozor (desetine mikrosekundi) čini „single trigger“ greške realističnim kada su uparene sa CPU affinity pinning-om ili hypervisor-assisted preemption-om.
- **Side effects** – Usporavanje utiče samo na zlonamerni put, pa ukupne performanse sistema ostaju nepromenjene; odbrambeni timovi će retko primetiti osim ako ne nadgledaju rast namespace-a.
- **Cleanup** – Zadržite handle-ove za svaki direktorijum/objekat koji napravite kako biste kasnije mogli pozvati `NtMakeTemporaryObject`/`NtClose`. U suprotnom, neograničeni lanci direktorijuma mogu preživeti restart sistema.

## Defensive notes

- Kernel kod koji zavisi od imenovanih objekata treba ponovo validirati bezbednosno osetljivo stanje *nakon* open-a, ili uzeti referencu pre provere (zatvarajući TOCTOU prozor).
- Primorajte ograničenja na dubinu/dužinu OM putanje pre dereferenciranja imena pod kontrolom korisnika. Odbacivanje predugih imena prisiljava napadače da se vrate u mikrosekundni prozor.
- Instrumentujte rast namespace-a object manager-a (ETW `Microsoft-Windows-Kernel-Object`) da biste detektovali sumnjive lance sa hiljadama komponenti ispod `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
