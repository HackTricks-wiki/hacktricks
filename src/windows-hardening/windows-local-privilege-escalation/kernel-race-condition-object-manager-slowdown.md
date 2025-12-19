# Kern-racevoorwaarde-uitbuiting via Object Manager se stadige paaie

{{#include ../../banners/hacktricks-training.md}}

## Waarom die uitbreiding van die race-venster saak maak

Baie Windows kernel LPE's volg die klassieke patroon `check_state(); NtOpenX("name"); privileged_action();`. Op moderne hardeware los 'n koue `NtOpenEvent`/`NtOpenSection` 'n kort naam in ~2 µs op, wat byna geen tyd oorlaat om die gecheckte toestand om te skakel voordat die veilige aksie plaasvind nie. Deur doelbewus die Object Manager Namespace (OMNS) opsoek in stap 2 te laat neem tien-talle mikrosekondes, kry die aanvaller genoeg tyd om konsekwent andersins onbetroubare races te wen sonder dat duisende pogings nodig is.

## Object Manager opsoek interne werking in 'n neutedop

* **OMNS-structuur** – Name soos `\BaseNamedObjects\Foo` word gids-vir-gids opgelos. Elke komponent veroorsaak dat die kernel 'n *Object Directory* vind/oopmaak en Unicode-stringe vergelyk. Simboliese skakels (bv. skyfletters) kan onderweg gevolg word.
* **UNICODE_STRING limit** – OM-paaie word gedra binne 'n `UNICODE_STRING` waarvan die `Length` 'n 16-bit waarde is. Die absolute limiet is 65 535 bytes (32 767 UTF-16 codepoints). Met voorvoegsels soos `\BaseNamedObjects\` beheer 'n aanvaller steeds ≈32 000 karakters.
* **Aanvaller-vereistes** – Enige gebruiker kan objekte skep onder skryfbare gidse soos `\BaseNamedObjects`. Wanneer die kwesbare kode 'n naam binne gebruik, of 'n simboliese skakel volg wat daar land, beheer die aanvaller die opsoekprestasie sonder spesiale voorregte.

## Vertraagings-primitive #1 – Enkele maksimum komponent

Die koste om 'n komponent op te los is grofweg lineêr met sy lengte omdat die kernel 'n Unicode-vergelyking teen elke inskrywing in die ouer-gids moet uitvoer. Deur 'n event te skep met 'n 32 kB-lange naam verhoog die `NtOpenEvent`-latensie onmiddellik van ~2 µs tot ~35 µs op Windows 11 24H2 (Snapdragon X Elite testbed).
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
- Symbolic links or reparse points kan 'n kort “victim”-naam na hierdie reuse-komponent wys sodat die slowdown deursigtig toegepas word.
- Omdat alles in gebruikers-skryfbare namespaces leef, werk die payload vanaf 'n standaard gebruikersintegriteitsvlak.

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
Wenke:

* Wissel die karakter per vlak (`A/B/C/...`) as die ouer gids begin duplikate verwerp.
* Hou 'n handvatselreeks sodat jy die ketting skoon na uitbuiting kan verwyder om te voorkom dat die naamruimte besoedel word.

## Meting van jou race window

Voeg 'n vinnige harnas in jou exploit in om te meet hoe groot die window op die slagoffer se hardware word. Die onderstaande snippet open die teikenobjek `iterations` keer en gee die gemiddelde per-open koste terug deur gebruik te maak van `QueryPerformanceCounter`.
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
Die resultate voed direk in jou race orchestration strategy (bv. aantal werkerdrade wat benodig word, slaapintervalle, hoe vroeg jy die gedeelde state moet flip).

## Exploitation workflow

1. **Locate the vulnerable open** – Trace the kernel path (via symbols, ETW, hypervisor tracing, or reversing) until you find an `NtOpen*`/`ObOpenObjectByName` call that walks an attacker-controlled name or a symbolic link in a user-writable directory.
2. **Replace that name with a slow path**
- Skep die lang komponent- of gidsketting onder `\BaseNamedObjects` (of ’n ander beskikbare OM-root).
- Skep ’n symbolic link sodat die naam wat die kernel verwag nou na die slow path oplos. Jy kan die kwetsbare driver se directory lookup na jou struktuur wys sonder om die oorspronklike te raak.
3. **Trigger the race**
- Thread A (victim) voer die kwetsbare kode uit en blokkeer binne die slow lookup.
- Thread B (attacker) flips die guarded state (bv. ruil ’n file handle, herskryf ’n symbolic link, toggle object security) terwyl Thread A besig is.
- Wanneer Thread A hervat en die privileged action uitvoer, sien dit stale state en voer die attacker-controlled operasie uit.
4. **Clean up** – Verwyder die gidsketting en symbolic links om te verhoed dat jy verdagte artefakte agterlaat of geldige IPC-gebruikers breek.

## Operational considerations

- **Combine primitives** – Jy kan ’n lang naam per vlak in ’n gidsketting gebruik vir selfs hoër latency totdat jy die `UNICODE_STRING` grootte uitgeput het.
- **One-shot bugs** – Die vergrote venster (tientalle microsekondes) maak “single trigger” bugs realisties wanneer dit gepaard gaan met CPU affinity pinning of hypervisor-assisted preemption.
- **Side effects** – Die slowdown raak slegs die kwaadwillige pad, so die algehele stelselprestasie bly onaangetas; verdedigers sal selde opmerk tensy hulle namespace growth monitor.
- **Cleanup** – Hou handles na elke gids/object wat jy skep sodat jy later `NtMakeTemporaryObject`/`NtClose` kan aanroep. Onbegrensde gidskettings kan andersins oor herlaaitye bly voortbestaan.

## Defensive notes

- Kernel code wat op named objects staatmaak moet security-sensitive state *her-valideer na die open*, of ’n referensie neem voor die check (waardeur die TOCTOU-gaping gesluit word).
- Handhaaf boonste grense op OM path depth/length voordat user-controlled names gedereference word. Weiering van oormatig lang name dwing aanvallers terug in die microsecond-venster.
- Instrumenteer object manager namespace growth (ETW `Microsoft-Windows-Kernel-Object`) om verdagte duisende-komponentkettings onder `\BaseNamedObjects` te detect.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
