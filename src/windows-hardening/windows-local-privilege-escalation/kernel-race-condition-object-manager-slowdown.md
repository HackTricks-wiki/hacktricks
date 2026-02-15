# Eksploatacija race uslova kernela putem sporih puteva Object Manager-a

{{#include ../../banners/hacktricks-training.md}}

## Zašto je važno proširiti vremenski prozor trke

Mnogi Windows kernel LPEs slede klasični obrazac `check_state(); NtOpenX("name"); privileged_action();`. Na modernom hardveru hladan `NtOpenEvent`/`NtOpenSection` razrešava kratak naziv za ~2 µs, ostavljajući gotovo nikakvo vreme da se promeni provereno stanje pre nego što se izvrši zaštićena akcija. Namernim forsiranjem lookup-a Object Manager Namespace (OMNS) u koraku 2 da traje desetine mikrosekundi, napadač dobija dovoljno vremena da dosledno pobedi inače nepouzdane trke bez potrebe za hiljadama pokušaja.

## Interna logika lookup-a Object Manager-a ukratko

* **OMNS structure** – Imena poput `\BaseNamedObjects\Foo` se razrešavaju direktorijum-po-direktorijum. Svaka komponenta navodi kernel da pronađe/otvori *Object Directory* i uporedi Unicode stringove. Simboličke veze (npr. slova drajva) mogu biti pređene na tom putu.
* **UNICODE_STRING limit** – OM path-ovi se nose unutar `UNICODE_STRING` čiji je `Length` 16-bitna vrednost. Apsolutni limit je 65 535 bajta (32 767 UTF-16 codepoint-a). Sa prefiksima kao `\BaseNamedObjects\`, napadač i dalje kontroliše ≈32 000 karaktera.
* **Attacker prerequisites** – Bilo koji korisnik može kreirati objekte ispod direktorijuma u koje se može pisati, kao što je `\BaseNamedObjects`. Kada ranjiv kod koristi ime unutar toga, ili prati simboličku vezu koja vodi tamo, napadač kontroliše performanse lookup-a bez posebnih privilegija.

## Slowdown primitive #1 – Single maximal component

Trošak razrešavanja jedne komponente je približno linearan u odnosu na njenu dužinu zato što kernel mora izvršiti Unicode poređenje sa svakim unosom u roditeljskom direktorijumu. Kreiranje event-a sa imenom od 32 kB odmah povećava latenciju `NtOpenEvent` sa ~2 µs na ~35 µs na Windows 11 24H2 (Snapdragon X Elite testbed).
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
- Simbolički linkovi ili reparse points mogu usmeriti kratak „victim“ naziv na ovu gigantsku komponentu tako da se usporavanje primenjuje transparentno.
- Pošto se sve nalazi u user-writable namespaces, payload radi sa standardnim nivoom integriteta korisnika.

## Slowdown primitive #2 – Duboke rekurzivne direktorijume

Agresivnija varijanta alocira lanac od hiljada direktorijuma (`\BaseNamedObjects\A\A\...\X`). Svaki korak pokreće logiku rešavanja direktorijuma (provere ACL, hash lookups, reference counting), tako da je latencija po nivou veća nego kod poređenja jedne string komponente. Sa ~16 000 nivoa (ograničeno istom `UNICODE_STRING` veličinom), empirijska merenja premašuju barijeru od 35 µs postignutu dugim pojedinačnim komponentama.
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
* Sačuvajte handle array tako da možete uredno obrisati lanac nakon exploitation-a i izbeći zagađivanje namespace-a.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories podržavaju **shadow directories** (fallback lookups) i bucketed hash tabele za unose. Iskoristite oba, plus 64-component symbolic-link reparse limit, da množite usporavanje bez prekoračenja dužine `UNICODE_STRING`:

1. Kreirajte dva direktorijuma pod `\BaseNamedObjects`, npr. `A` (shadow) i `A\A` (target). Kreirajte drugi koristeći prvi kao shadow directory (`NtCreateDirectoryObjectEx`), tako da nedostajući lookupi u `A` padaju na `A\A`.
2. Popunite svaki direktorijum hiljadama imena koja kolidiraju i koja završavaju u istom hash bucket-u (npr. menjajući završne cifre dok zadržavate istu vrednost `RtlHashUnicodeString`). Lookupi sada degradiraju na O(n) linearne skenove unutar jednog direktorijuma.
3. Napravite lanac od ~63 object manager symbolic links koje se ponovo parsiraju u dugi `A\A\…` sufiks, trošeći reparse budžet. Svako reparse-ovanje restartuje parsiranje od vrha, multiplicirajući trošak kolizije.
4. Lookup poslednjeg komponenta (`...\\0`) sada traje **minutama** na Windows 11 kada je po direktorijumu prisutno 16 000 kolizija, što praktično garantuje pobedu u trci za one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Zašto je važno*: Usporavanje od nekoliko minuta pretvara one-shot race-based LPEs u determinističke exploits.

### Beleške ponovnog testiranja 2025 & gotovi alati

- James Forshaw je ponovo objavio tehniku sa ažuriranim vremenskim merenjima na Windows 11 24H2 (ARM64). Osnovna otvaranja ostaju ~2 µs; komponenta od 32 kB povećava ovo na ~35 µs, a shadow-dir + collision + 63-reparse chains i dalje dostižu ~3 minute, što potvrđuje da primitives opstaju u trenutnim build-ovima. Izvorni kod i perf harness nalaze se u osveženom Project Zero postu.
- Možete skriptovati postavljanje koristeći javni `symboliclink-testing-tools` paket: `CreateObjectDirectory.exe` da kreira shadow/target par i `NativeSymlink.exe` u petlji da emituje 63-hop chain. Ovo izbegava ručno pisane `NtCreate*` wrapper-e i održava ACLs konzistentnim.

## Merenje vašeg race window-a

Ugradite kratak harness unutar vašeg exploit-a da izmerite koliko veliki prozor postane na hardveru žrtve. Snippet ispod otvara ciljani objekat `iterations` puta i vraća prosečan trošak po otvaranju koristeći `QueryPerformanceCounter`.
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
Rezultati se direktno koriste za vašu race orchestration strategiju (npr. broj worker threads koji su potrebni, sleep intervals, koliko rano treba da promenite shared state).

## Tok eksploatacije

1. **Pronađite vulnerabilno open** – Trasirajte kernel path (preko symbols, ETW, hypervisor tracing, ili reversing) dok ne nađete poziv `NtOpen*`/`ObOpenObjectByName` koji prolazi kroz ime koje kontroliše napadač ili kroz symbolic link u direktorijumu koji je user-writable.
2. **Zamenite to ime sporim path-om**
- Kreirajte dugačku komponentu ili lanac direktorijuma pod `\BaseNamedObjects` (ili drugim writable OM root-om).
- Kreirajte symbolic link tako da ime koje kernel očekuje sada rešava na slow path. Možete usmeriti directory lookup ranjivog driver-a na vašu strukturu bez diranja originalne destinacije.
3. **Trigger the race**
- Thread A (žrtva) izvršava ranjiv kod i blokira se unutar slow lookup-a.
- Thread B (napadač) flip-uje guarded state (npr. zamenjuje file handle, prepisuje symbolic link, menja object security) dok je Thread A zauzet.
- Kada se Thread A nastavi i izvrši privilegovanu akciju, uoči stale state i izvrši operaciju kontrolisanu od strane napadača.
4. **Očistite** – Obrišite lanac direktorijuma i symbolic link-ove da ne biste ostavili sumnjive artefakte ili prekinuli legitimne IPC korisnike.

## Operativna razmatranja

- **Kombinujte primitive** – Možete koristiti dugo ime *po nivou* u lancu direktorijuma za još veću latenciju dok ne iscrpite veličinu `UNICODE_STRING`.
- **One-shot bugovi** – Prošireni prozor (desetine mikrosekundi do minuta) čini “single trigger” bugove realističnim kada se sparuju sa CPU affinity pinning-om ili hypervisor-assisted preemption-om.
- **Sporedni efekti** – Usporavanje utiče samo na malicious path, tako da ukupne performanse sistema ostaju neoštećene; defenders će retko primetiti osim ako ne prate rast namespace-a.
- **Očuvanje** – Zadržite handle-ove za svaki direktorijum/object koji kreirate kako biste kasnije mogli pozvati `NtMakeTemporaryObject`/`NtClose`. Neograničeni lanci direktorijuma mogu inače opstati i posle reboot-a.
- **File-system races** – Ako se ranjivi path na kraju rešava kroz NTFS, možete postaviti Oplock (npr. `SetOpLock.exe` iz istog toolkita) na backing file dok OM slowdown radi, zamrzavajući consumer za dodatne milisekunde bez menjanja OM grafa.

## Odbrambene napomene

- Kernel kod koji se oslanja na named objects treba da ponovo verifikuje security-sensitive state *nakon* open-a, ili da uzme referencu pre provere (zatvarajući TOCTOU gap).
- Primena gornjih granica za OM path depth/length pre dereferenciranja user-controlled imena. Odbacivanje predugačkih imena primorava napadače da se vrate u mikrosekundni prozor.
- Instrumentujte object manager namespace growth (ETW `Microsoft-Windows-Kernel-Object`) da biste detektovali sumnjive lance od hiljada komponenti pod `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
