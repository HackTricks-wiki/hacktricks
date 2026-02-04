# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Zašto je važno proširiti vremenski prozor za race

Mnogi Windows kernel LPE-ovi slede klasičan obrazac `check_state(); NtOpenX("name"); privileged_action();`. Na modernom hardveru cold `NtOpenEvent`/`NtOpenSection` rešava kratak naziv za ~2 µs, ostavljajući gotovo nikakvo vreme da se promeni provereno stanje pre nego što se izvrši zaštićena radnja. Namernim forsiranjem lookup-a Object Manager Namespace (OMNS) u koraku 2 da traje desetine mikrosekundi, napadač dobija dovoljno vremena da konzistentno pobedi u inače nestabilnim races bez potrebe za hiljadama pokušaja.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Nazivi kao što su `\BaseNamedObjects\Foo` rešavaju se direktorijum po direktorijum. Svaka komponenta navodi kernel da pronađe/otvori *Object Directory* i uporedi Unicode stringove. Symbolic links (npr. slova drajvova) mogu biti pređeni usput.
* **UNICODE_STRING limit** – OM paths se nose unutar `UNICODE_STRING` čije je polje `Length` 16-bitna vrednost. Apsolutni limit je 65 535 bajtova (32 767 UTF-16 codepoint-ova). Sa prefiksima poput `\BaseNamedObjects\`, napadač i dalje kontroliše ≈32 000 karaktera.
* **Attacker prerequisites** – Bilo koji korisnik može kreirati objekte ispod zapisivih direktorijuma kao što je `\BaseNamedObjects`. Kada ranjiv kod koristi ime unutar tog direktorijuma, ili sledi symbolic link koji vodi tamo, napadač kontroliše performanse lookup-a bez posebnih privilegija.

## Slowdown primitive #1 – Single maximal component

Trošak rešavanja jedne komponente je otprilike linearan u odnosu na njenu dužinu zato što kernel mora da izvrši Unicode poređenje protiv svakog unosa u parent direktorijumu. Kreiranje event-a sa imenom dužine 32 kB odmah povećava latenciju `NtOpenEvent` sa ~2 µs na ~35 µs na Windows 11 24H2 (Snapdragon X Elite testbed).
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
- Simboličke veze ili reparse points mogu usmeriti kratko „victim” ime na ovu ogromnu komponentu tako da se usporavanje primenjuje transparentno.
- Pošto se sve nalazi u prostorima imena upisivim od strane korisnika, payload radi sa standardnim nivoom integriteta korisnika.

## Slowdown primitive #2 – Deep recursive directories

A more aggressive variant allocates a chain of thousands of directories (`\BaseNamedObjects\A\A\...\X`). Each hop triggers directory resolution logic (ACL checks, hash lookups, reference counting), so the per-level latency is higher than a single string compare. With ~16 000 levels (limited by the same `UNICODE_STRING` size), empirical timings surpass the 35 µs barrier achieved by long single components.
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
Tips:

* Naizmenično koristite karakter po nivou (`A/B/C/...`) ako roditeljski direktorijum počne da odbija duplikate.
* Sačuvajte handle array tako da možete uredno da obrišete lanac nakon exploitation kako biste izbegli zagađenje namespace-a.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories support **shadow directories** (fallback lookups) and bucketed hash tables for entries. Abuse both plus the 64-component symbolic-link reparse limit to multiply slowdown without exceeding the `UNICODE_STRING` length:

1. Create two directories under `\BaseNamedObjects`, e.g. `A` (shadow) and `A\A` (target). Create the second using the first as the shadow directory (`NtCreateDirectoryObjectEx`), so missing lookups in `A` fall through to `A\A`.
2. Fill each directory with thousands of **colliding names** that land in the same hash bucket (e.g., varying trailing digits while keeping the same `RtlHashUnicodeString` value). Lookups now degrade to O(n) linear scans inside a single directory.
3. Build a chain of ~63 **object manager symbolic links** that repeatedly reparse into the long `A\A\…` suffix, consuming the reparse budget. Each reparse restarts parsing from the top, multiplying the collision cost.
4. Lookup of the final component (`...\\0`) now takes **minutes** on Windows 11 when 16 000 collisions are present per directory, providing a practically guaranteed race win for one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Zašto je važno*: Usporavanje koje traje nekoliko minuta pretvara one-shot race-based LPEs u determinističke exploits.

## Merenje vašeg race window-a

Umetnite kratak harness u vaš exploit da izmerite koliko veliki prozor postaje na žrtvinom hardveru. Sledeći snippet otvara ciljani objekat `iterations` puta i vraća prosečan trošak po otvaranju koristeći `QueryPerformanceCounter`.
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
Rezultati se direktno uklapaju u vašu race orchestration strategiju (npr. broj worker threads koji su potrebni, sleep intervals, koliko rano treba flip-ovati shared state).

## Tok eksploatacije

1. **Pronađite ranjivi open** – Pratite kernel putanju (putem symbols, ETW, hypervisor tracing, ili reversing) dok ne nađete poziv `NtOpen*`/`ObOpenObjectByName` koji prolazi kroz ime kontrolisano od napadača ili kroz symbolic link u direktorijumu koji je upisiv od strane korisnika.
2. **Zamenite to ime usporenom stazom**
- Kreirajte dugu komponentu ili lanac direktorijuma pod `\BaseNamedObjects` (ili drugim writable OM root-om).
- Kreirajte symbolic link tako da ime koje kernel očekuje sada rešava na usporenu stazu. Možete usmeriti vulnerable driver-ov directory lookup na vašu strukturu bez diranja originalne mete.
3. **Pokrenite race**
- Thread A (victim) izvršava ranjivi kod i blokira se unutar usporenog lookup-a.
- Thread B (attacker) flip-uje guarded state (npr. zameni file handle, prepiše symbolic link, toggluje object security) dok je Thread A zauzet.
- Kada se Thread A nastavi i izvrši privilegovanu akciju, uoči zastarelo stanje i izvrši operaciju kontrolisanu od strane napadača.
4. **Očistite** – Obrišite lanac direktorijuma i symbolic link-ove da ne ostavite sumnjive artefakte ili da ne pokvarite legitimne IPC korisnike.

## Operativna razmatranja

- **Kombinujte primitive** – Možete koristiti dugo ime *per level* u lancu direktorijuma za još veću latenciju dok ne iscrpite veličinu `UNICODE_STRING`.
- **One-shot bugs** – Prošireni prozor (desetine mikrosekundi do minuta) čini “single trigger” bagove realističnim kada su upareni sa CPU affinity pinning-om ili hypervisor-assisted preemption-om.
- **Sporedni efekti** – Usporavanje utiče samo na zlonamerni path, tako da ukupne performanse sistema ostaju nepromenjene; odbrambeni timovi će retko primetiti osim ako ne prate rast namespace-a.
- **Očistite** – Zadržite handle-ove za svaki direktorijum/objekat koji kreirate tako da možete pozvati `NtMakeTemporaryObject`/`NtClose` nakon toga. U suprotnom, neograničeni lanci direktorijuma mogu opstati preko reboot-a.

## Odbrambene napomene

- Kernel kod koji zavisi od named objects treba ponovo verifikovati security-sensitive stanje *nakon* open-a, ili uzeti referencu pre provere (zatvarajući TOCTOU gap).
- Nametnite gornje granice na OM path depth/length pre dereferenciranja imena kontrolisanih od strane korisnika. Odbacivanje predugačkih imena primorava napadače da se vrate u mikrosekundni prozor.
- Instrumentujte rast object manager namespace-a (ETW `Microsoft-Windows-Kernel-Object`) da detektujete sumnjive lance od hiljada komponenti pod `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
