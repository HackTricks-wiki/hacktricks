# Kernel-wedlooptoestand-uitbuiting via Object Manager se stadige paaie

{{#include ../../banners/hacktricks-training.md}}

## Hoekom dit saak maak om die race-venster te rek

Baie Windows kernel LPE's volg die klassieke patroon `check_state(); NtOpenX("name"); privileged_action();`. Op moderne hardeware los 'n koue `NtOpenEvent`/`NtOpenSection` 'n kort naam op in ~2 µs, wat byna geen tyd oorlaat om die geverifieerde toestand te verander voordat die veilige aksie plaasvind nie. Deur doelbewus die Object Manager-naamruimte (OMNS) so te dwing dat die lookup in stap 2 tienduisende mikrosekondes neem, kry die aanvaller genoeg tyd om konsekwent andersins onbetroubare races te wen sonder om duisende pogings nodig te hê.

## Object Manager lookup-internals in 'n neutedop

* **OMNS structure** – Name soos `\BaseNamedObjects\Foo` word gids-vir-gids opgelos. Elke komponent veroorsaak dat die kernel 'n *Object Directory* vind/open en Unicode-stringe vergelyk. Symboliese skakels (bv. skyfletters) kan onderweg gekruis word.
* **UNICODE_STRING limit** – OM-paadjies word gedra binne 'n `UNICODE_STRING` waarvan die `Length` 'n 16-bit waarde is. Die absolute limiet is 65 535 bytes (32 767 UTF-16 kodepunte). Met voorvoegsels soos `\BaseNamedObjects\` beheer 'n aanvaller steeds ≈32 000 karakters.
* **Attacker prerequisites** – Enige gebruiker kan objekte skep onder skryfbare gidse soos `\BaseNamedObjects`. Wanneer die kwesbare kode 'n naam binne daardie plek gebruik, of 'n symboliese skakel volg wat daar uitkom, beheer die aanvaller die lookup-prestasie sonder enige spesiale voorregte.

## Slowdown primitive #1 – Enkele maximale komponent

Die koste om 'n komponent op te los is ongeveer lineêr met sy lengte omdat die kernel 'n Unicode-vergelyking teen elke inskrywing in die ouer-gids moet uitvoer. Om 'n event met 'n 32 kB-lange naam te skep verhoog onmiddellik die `NtOpenEvent`-latensie van ~2 µs na ~35 µs op Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktiese notas*

- Jy kan die lengtegrens bereik deur enige benoemde kernel-objek te gebruik (events, sections, semaphores…).
- Symbolic links of reparse points kan 'n kort “victim”-naam na hierdie reuse-komponent wys, sodat die vertraging deurskynend toegepas word.
- Omdat alles in user-writable namespaces bestaan, werk die payload vanaf 'n standard user integrity level.

## Vertragingsprimitief #2 – Diepe rekursiewe gidse

'n Meer agressiewe variant ken 'n ketting van duisende gidse toe (`\BaseNamedObjects\A\A\...\X`). Elke hop aktiveer directory resolution logic (ACL checks, hash lookups, reference counting), so die latensie per vlak is hoër as by 'n enkele stringvergelyking. Met ~16 000 vlakke (beperk deur dieselfde `UNICODE_STRING` grootte), oorskry empiriese tydmetings die 35 µs-grens wat deur lang enkele komponente behaal is.
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
Wenke:

* Wissel die karakter per vlak (`A/B/C/...`) as die ouer-gids begin om duplikate te verwerp.
* Hou 'n handle-array sodat jy die ketting skoon kan uitvee na eksploitasië om te verhoed dat die namespace besmet word.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minute in plaas van mikrosekondes)

Object directories ondersteun **shadow directories** (fallback lookups) en bucketed hash tables vir entries. Misbruik beide tesame met die 64-component symbolic-link reparse limit om die vertragings te vermenigvuldig sonder om die `UNICODE_STRING` lengte te oorskry:

1. Skep twee gidse onder `\BaseNamedObjects`, bv. `A` (shadow) en `A\A` (target). Skep die tweede deur die eerste as die shadow directory te gebruik (`NtCreateDirectoryObjectEx`), sodat ontbrekende lookups in `A` deurval na `A\A`.
2. Vul elke gids met duisende **colliding names** wat in dieselfde hash bucket beland (bv. veranderende agtervoegsels terwyl jy dieselfde `RtlHashUnicodeString` waarde behou). Lookups degradeer nou na O(n) lineêre skanderings binne 'n enkele gids.
3. Bou 'n ketting van ~63 **object manager symbolic links** wat herhaaldelik reparse na die lang `A\A\…` agtervoegsel, en sodoende die reparse-begroting opbruik. Elke reparse begin parsing weer van die begin af, wat die koste van die botsings vermenigvuldig.
4. Lookup van die finale komponent (`...\\0`) neem nou **minute** op Windows 11 wanneer 16 000 botsings per gids teenwoordig is, wat 'n prakties gewaarborgde race win vir one-shot kernel LPEs bied.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Waarom dit saak maak*: 'n minute-lange vertraging verander one-shot race-based LPEs in deterministiese exploits.

## Meet jou race window

Voeg 'n vinnige harness in jou exploit in om te meet hoe groot die window op die slagoffer se hardware word. Die snippet hieronder maak die target object `iterations` keer oop en gee die gemiddelde koste per oopmaak terug deur `QueryPerformanceCounter` te gebruik.
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
Die resultate voed direk in jou race orchestration strategy (bv. aantal werkerdrade benodig, slaapintervalle, hoe vroeg jy die gedeelde toestand moet omskakel).

## Exploitation workflow

1. **Lokaliseer die kwesbare open** – Spoor die kernel-pad na (via symbols, ETW, hypervisor tracing, of reversing) totdat jy 'n `NtOpen*`/`ObOpenObjectByName` oproep vind wat 'n deur-aanvaller-beheerde naam of 'n symboliese skakel in 'n gebruiker-skryfbare gids deurloop.
2. **Vervang daardie naam met 'n stadiger pad**
- Skep die lang komponent- of gidsketting onder `\BaseNamedObjects` (of 'n ander skryfbare OM root).
- Skep 'n symboliese skakel sodat die naam wat die kernel verwag nou na die stadiger pad oplos. Jy kan die kwesbare driver se gidsopsoek na jou struktuur wys sonder om die oorspronklike teiken aan te raak.
3. **Trigger the race**
- Thread A (slagoffer) voer die kwesbare kode uit en blokkeer binne die stadiger opsoek.
- Thread B (aanvaller) skakel die beskermde toestand om (bv., ruil 'n file handle om, herskryf 'n symboliese skakel, wissel object security) terwyl Thread A besig is.
- Wanneer Thread A hervat en die bevoorregte aksie uitvoer, sien dit verouderde toestand en voer die deur-aanvaller-beheerde operasie uit.
4. **Clean up** – Verwyder die gidsketting en symboliese skakels om te voorkom dat daar verdaglike artefakte agterbly of wettige IPC-gebruikers gebreek word.

## Operasionele oorwegings

- **Combine primitives** – Jy kan 'n lang naam *per level* in 'n gidsketting gebruik vir selfs hoër latensie totdat jy die `UNICODE_STRING` grootte uitgeput het.
- **One-shot bugs** – Die uitgebreide venster (tens of microseconds tot minutes) maak “single trigger” bugs realisties wanneer dit saam met CPU affinity pinning of hypervisor-assisted preemption gebruik word.
- **Side effects** – Die vertraging raak slegs die kwaadwillige pad, so die algehele stelselprestasie bly onaangetas; verdedigers sal selde opmerk tensy hulle namespace growth monitor.
- **Cleanup** – Hou handles vir elke gids/object wat jy skep sodat jy later `NtMakeTemporaryObject`/`NtClose` kan aanroep. Andersins kan onbeperkte gidskettings oor herstarts bly voortbestaan.

## Verdedigingsnotas

- Kernel-kode wat op named objects staatmaak, moet sekuriteits-sensitiewe toestand *na* die open her-valideer, of 'n verwysing neem vóór die check (die TOCTOU-gaping toemaak).
- Stel bo-grense op OM-paddiepte/-lengte af voordat user-controlled names gedereferensieer word. Die verwerping van oorlang name dwing aanvallers terug in die microsecond-venster.
- Instrumenteer object manager namespace growth (ETW `Microsoft-Windows-Kernel-Object`) om verdagte duisende-komponente kettings onder `\BaseNamedObjects` te detecteer.

## Verwysings

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
