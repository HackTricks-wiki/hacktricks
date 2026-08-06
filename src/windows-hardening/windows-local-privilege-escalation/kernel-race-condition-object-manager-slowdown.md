# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Waarom dit belangrik is om die race window te verleng

Baie Windows-kernel-LPEs volg die klassieke patroon `check_state(); NtOpenX("name"); privileged_action();`. Op moderne hardeware los ’n koue `NtOpenEvent`/`NtOpenSection` ’n kort naam in ongeveer 2 µs op, wat byna geen tyd laat om die nagegane toestand om te skakel voordat die veilige aksie plaasvind nie. Deur die Object Manager Namespace (OMNS)-opsoek in stap 2 doelbewus tien­ talle mikrosekondes te laat duur, kry die aanvaller genoeg tyd om konsekwent races te wen wat andersins onbetroubaar sou wees, sonder dat duisende pogings nodig is.<sup>[[1]](#references)</sup>

## Object Manager-opsoekinterne in ’n neutedop

* **OMNS-struktuur** – Name soos `\BaseNamedObjects\Foo` word gids vir gids opgelos. Elke komponent veroorsaak dat die kernel ’n *Object Directory* vind/open en Unicode-stringe vergelyk. Simboliese skakels (byvoorbeeld dryfletters) kan onderweg gevolg word.
* **UNICODE_STRING-limiet** – OM-paaie word binne ’n `UNICODE_STRING` gedra waarvan `Length` ’n 16-bis-waarde is. Die absolute limiet is 65 535 grepe (32 767 UTF-16-kodepunte). Met voorvoegsels soos `\BaseNamedObjects\` beheer ’n aanvaller steeds ongeveer 32 000 karakters.
* **Aanvaller-voorvereistes** – Enige gebruiker kan objekte skep onder skryfbare gidse soos `\BaseNamedObjects`. Wanneer die kwesbare kode ’n naam binne so ’n gids gebruik, of ’n simboliese skakel volg wat daar land, beheer die aanvaller die opsoekwerkverrigting sonder spesiale regte.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Enkel maksimumkomponent

Die koste om ’n komponent op te los is rofweg lineêr met sy lengte, omdat die kernel ’n Unicode-vergelyking teen elke inskrywing in die ouergids moet uitvoer. Deur ’n event met ’n naam van 32 kB te skep, verhoog die `NtOpenEvent`-latensie onmiddellik van ongeveer 2 µs tot ongeveer 35 µs op Windows 11 24H2 (Snapdragon X Elite-toetsplatform).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktiese notas*

- Jy kan die lengtelimiet bereik deur enige benoemde kernobjek te gebruik (events, sections, semaphores…).
- Symbolic links of reparse points kan ’n kort “victim”-naam na hierdie reuse-komponent laat wys, sodat die vertraging deursigtig toegepas word.
- Omdat alles in namespaces woon wat deur die gebruiker geskryf kan word, werk die payload vanaf ’n standaard user integrity level.<sup>[[1]](#references)</sup>

## Vertragingsprimitief #2 – Diep rekursiewe gidse

’n Meer aggressiewe variant allokeer ’n ketting van duisende gidse (`\BaseNamedObjects\A\A\...\X`). Elke stap aktiveer directory resolution logic (ACL checks, hash lookups, reference counting), dus is die latency per vlak hoër as dié van ’n enkele string compare. Met ongeveer 16 000 vlakke (beperk deur dieselfde `UNICODE_STRING`-grootte), oorskry empiriese timings die 35 µs-grens wat deur lang enkelkomponente bereik word.
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

* Wissel die karakter per vlak af (`A/B/C/...`) as die ouergids duplikate begin weier.
* Hou ’n handvatsel-skikking sodat jy die ketting ná exploitation netjies kan verwyder om te voorkom dat die naamruimte besoedel word.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow-gidse, hash collisions en symlink-reparses (minute in plaas van mikrosekondes)

Object-gidse ondersteun **shadow directories** (fallback lookups) en hash tables met buckets vir entries. Misbruik albei, tesame met die limiet van 64-komponent symbolic-link reparse, om die slowdown te vermenigvuldig sonder om die `UNICODE_STRING`-lengte te oorskry:

1. Skep twee gidse onder `\BaseNamedObjects`, byvoorbeeld `A` (shadow) en `A\A` (target). Skep die tweede een deur die eerste as die shadow directory te gebruik (`NtCreateDirectoryObjectEx`), sodat ontbrekende lookups in `A` na `A\A` deurval.
2. Vul elke gids met duisende **colliding names** wat in dieselfde hash bucket beland (byvoorbeeld deur die agterste syfers te varieer terwyl dieselfde `RtlHashUnicodeString`-waarde behou word). Lookups verswak nou tot O(n) lineêre scans binne ’n enkele gids.
3. Bou ’n ketting van ongeveer 63 **object manager symbolic links** wat herhaaldelik na die lang `A\A\…`-suffix herparse, en sodoende die reparse-budget verbruik. Elke reparse begin parsing weer van bo af, wat die collision-koste vermenigvuldig.
4. Lookup van die finale komponent (`...\\0`) neem nou **minute** op Windows 11 wanneer 16 000 collisions per gids teenwoordig is, wat ’n feitlik gewaarborgde race-win vir eenmalige kernel LPEs bied.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Waarom dit belangrik is*: ’n vertraging van etlike minute verander eenmalige race-gebaseerde LPEs in deterministiese exploits.<sup>[[1]](#references)</sup>

### 2025-hertoetsnotas en gereedgemaakte tooling

- James Forshaw het die tegniek opnieuw gepubliseer met opgedateerde tydsberekeninge op Windows 11 24H2 (ARM64). Baseline-opens bly ongeveer 2 µs; ’n 32 kB-komponent verhoog dit tot ongeveer 35 µs, en shadow-dir + collision + 63-reparse chains bereik steeds ongeveer 3 minute, wat bevestig dat die primitives huidige builds oorleef. Bronkode en die perf harness is in die opgedateerde Project Zero-plasing.<sup>[[1]](#references)</sup>
- Jy kan die opstelling met die publieke `symboliclink-testing-tools`-bundle script: `CreateObjectDirectory.exe` om die shadow/target-paar te skep en `NativeSymlink.exe` in ’n loop om die 63-hop chain te genereer. Dit vermy handgeskrewe `NtCreate*` wrappers en hou ACLs konsekwent.<sup>[[2]](#references)</sup>

## Meet jou race window

Integreer ’n vinnige harness in jou exploit om te meet hoe groot die window op die slagoffer se hardeware word. Die snippet hieronder open die target object `iterations` keer en gee die gemiddelde koste per open terug met behulp van `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Die resultate vloei direk in jou race orchestration-strategie in (bv. die aantal worker threads wat benodig word, sleep intervals, en hoe vroeg jy die shared state moet omskakel).

## Exploitation workflow

1. **Locate the vulnerable open** – Trace die kernel path (via symbols, ETW, hypervisor tracing, of reversing) totdat jy ’n `NtOpen*`/`ObOpenObjectByName`-call vind wat ’n attacker-controlled name of ’n symbolic link in ’n user-writable directory deurloop.
2. **Replace that name with a slow path**
- Skep die lang component- of directory chain onder `\BaseNamedObjects` (of ’n ander writable OM root).
- Skep ’n symbolic link sodat die name wat die kernel verwag nou na die slow path resolve. Jy kan die vulnerable driver se directory lookup na jou struktuur wys sonder om aan die oorspronklike target te raak.
3. **Trigger the race**
- Thread A (victim) voer die vulnerable code uit en blokkeer binne die slow lookup.
- Thread B (attacker) verander die guarded state (bv. swap ’n file handle, herskryf ’n symbolic link, of wissel object security) terwyl Thread A besig gehou word.
- Wanneer Thread A hervat en die privileged action uitvoer, sien dit stale state en voer dit die attacker-controlled operation uit.
4. **Clean up** – Delete die directory chain en symbolic links om te voorkom dat verdagte artifacts agtergelaat word of dat legitieme IPC users gebreek word.<sup>[[1]](#references)</sup>

## Operational considerations

- **Combine primitives** – Jy kan ’n lang name *per level* in ’n directory chain gebruik vir selfs hoër latency totdat jy die `UNICODE_STRING`-grootte uitput.
- **One-shot bugs** – Die uitgebreide window (tientalle microseconds tot minute) maak “single trigger”-bugs realisties wanneer dit met CPU affinity pinning of hypervisor-assisted preemption gekombineer word.
- **Side effects** – Die slowdown beïnvloed slegs die malicious path, dus bly algehele system performance onaangeraak; defenders sal dit selde opmerk tensy hulle namespace growth monitor.
- **Cleanup** – Hou handles na elke directory/object wat jy skep sodat jy daarna `NtMakeTemporaryObject`/`NtClose` kan call. Unbounded directory chains kan andersins oor reboots heen bly bestaan.
- **File-system races** – As die vulnerable path uiteindelik deur NTFS resolve, kan jy ’n Oplock (bv. `SetOpLock.exe` van dieselfde toolkit) op die backing file stack terwyl die OM slowdown loop, wat die consumer vir addisionele milliseconds vries sonder om die OM graph te verander.<sup>[[2]](#references)</sup>

## Defensive notes

- Kernel code wat op named objects staatmaak, behoort security-sensitive state *after* die open te re-validate, of ’n reference voor die check te neem (sodat die TOCTOU gap gesluit word).
- Dwing upper bounds op OM path depth/length af voordat user-controlled names gedereference word. Die verwerping van overly long names dwing attackers terug na die microsecond window.
- Instrumenteer object manager namespace growth (ETW `Microsoft-Windows-Kernel-Object`) om suspicious thousands-of-components chains onder `\BaseNamedObjects` op te spoor.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
