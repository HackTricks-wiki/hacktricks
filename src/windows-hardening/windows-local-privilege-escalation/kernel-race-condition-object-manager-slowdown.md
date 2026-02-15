# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Why stretching the race window matters

Baie Windows kernel LPEs volg die klassieke patroon `check_state(); NtOpenX("name"); privileged_action();`. Op moderne hardeware los 'n koue `NtOpenEvent`/`NtOpenSection` 'n kort naam op in ~2 µs, wat byna geen tyd laat om die gekontroleerde toestand om te skakel voordat die beveiligde aksie plaasvind nie. Deur doelbewus die Object Manager Namespace (OMNS) lookup in stap 2 te dwing om tien-talle mikrosekondes te neem, kry die aanvaller genoeg tyd om konsekwent andersins onbetroubare races te wen sonder om duisende pogings nodig te hê.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Name soos `\BaseNamedObjects\Foo` word gids-vir-gids opgelos. Elke komponent veroorsaak dat die kernel 'n *Object Directory* vind/open en Unicode-strings vergelyk. Symbolic links (bv. skyfletters) kan onderweg gevolg word.
* **UNICODE_STRING limit** – OM paths word binne 'n `UNICODE_STRING` gedra waarvan die `Length` 'n 16-bit waarde is. Die absolute limiet is 65 535 bytes (32 767 UTF-16 codepoints). Met voorvoegsels soos `\BaseNamedObjects\` beheer 'n aanvaller steeds ≈32 000 karakters.
* **Attacker prerequisites** – Enige gebruiker kan objects skep onder skryfbare gidse soos `\BaseNamedObjects`. Wanneer die kwesbare kode 'n naam binne gebruik, of 'n symbolic link volg wat daar land, beheer die aanvaller die lookup-prestasie sonder spesiale voorregte.

## Slowdown primitive #1 – Single maximal component

Die koste om 'n komponent op te los is grofweg lineêr met sy lengte omdat die kernel 'n Unicode-vergelyking teen elke inskrywing in die ouer-gids moet uitvoer. Om 'n event met 'n 32 kB-lange naam te skep verhoog onmiddellik die `NtOpenEvent` latency van ~2 µs na ~35 µs op Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktiese notas*

- Jy kan die lengte-limiet bereik deur enige benoemde kernel-voorwerp te gebruik (events, sections, semaphores…).
- Symbolic links or reparse points can point a short “victim” name to this giant component so the slowdown is applied transparently.
- Omdat alles in user-writable namespaces leef, werk die payload vanaf 'n standaard user integrity level.

## Slowdown primitive #2 – Diepe rekursiewe gidse

'n Meer aggressiewe variant skep 'n ketting van duisende gidse (`\BaseNamedObjects\A\A\...\X`). Elke skakel aktiveer gidsresolusielogika (ACL checks, hash lookups, reference counting), sodat die wagtyd per vlak hoër is as by 'n enkele stringvergelyking. Met ~16 000 vlakke (beperk deur dieselfde `UNICODE_STRING` grootte), oortref empiriese tydmetings die 35 µs-grens wat deur lang enkele komponente behaal is.
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

* Wissel die karakter per vlak (`A/B/C/...`) as die ouerdirektorie begin duplikate te verwerp.
* Hou 'n handle-array sodat jy die ketting skoon kan verwyder ná uitbuiting om te voorkom dat die namespace besoedel word.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories support **shadow directories** (fallback lookups) and bucketed hash tables for entries. Misbruik albei plus die 64-component symbolic-link reparse limit om die vertraging te vermenigvuldig sonder om die `UNICODE_STRING` lengte te oorskry:

1. Skep twee directories onder `\BaseNamedObjects`, bv. `A` (shadow) en `A\A` (target). Skep die tweede deur die eerste as die shadow directory te gebruik (`NtCreateDirectoryObjectEx`), sodat ontbrekende lookups in `A` deurval na `A\A`.
2. Vul elke directory met duisende **colliding names** wat in dieselfde hash bucket beland (bv. wisselende agterste syfers terwyl dieselfde `RtlHashUnicodeString`-waarde behou word). Opsoeke verval nou na O(n) lineêre skanderings binne 'n enkele directory.
3. Bou 'n ketting van ~63 **object manager symbolic links** wat herhaaldelik herparseer na die lang `A\A\…` agtervoegsel, wat die reparse-begroting opeet. Elke reparse begin parsing weer van voor af en vermenigvuldig die koste van die botsings.
4. Die opsoek na die finale komponent (`...\\0`) neem nou **minutes** op Windows 11 wanneer 16 000 botsings per directory teenwoordig is, wat 'n prakties gewaarborgde race-wen vir one-shot kernel LPEs bied.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Waarom dit saak maak*: 'n vertraagting wat minute duur verander eenmalige, race-gebaseerde LPEs in deterministiese exploits.

### 2025 herstoets notas & kant-en-klare gereedskap

- James Forshaw het die tegniek herpos met opgedateerde tydwaardes op Windows 11 24H2 (ARM64). Baseline opens bly ~2 µs; 'n 32 kB komponent verhoog dit tot ~35 µs, en shadow-dir + collision + 63-reparse kettings bereik steeds ~3 minute, wat bevestig dat die primitives huidige builds oorleef. Source code en perf harness is in die verfriste Project Zero-post.
- Jy kan die opstelling skrip met die publieke `symboliclink-testing-tools` bundel: `CreateObjectDirectory.exe` om die shadow/target-paar te spawn en `NativeSymlink.exe` in 'n lus om die 63-hop ketting uit te stuur. Dit vermy hand-geskrewe `NtCreate*` wrappers en hou ACLs konsekwent.

## Meet jou race-venster

Voeg 'n vinnige harness in jou exploit in om te meet hoe groot die venster op die slagoffer-hardware word. Die kodefragment hieronder open die target object `iterations` keer en gee die gemiddelde per-open koste terug met behulp van `QueryPerformanceCounter`.
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
Die resultate voed direk in jou race-orchestrasiestrategie in (bv. aantal worker-threads wat benodig word, slaapintervalles, hoe vroeg jy die gedeelde toestand moet omskakel).

## Eksploitasie-werkvloei

1. **Vind die kwesbare open** – Volg die kernel-pad (via symbols, ETW, hypervisor tracing, of reversing) totdat jy 'n `NtOpen*`/`ObOpenObjectByName` oproep vind wat 'n deur die aanvaller beheerde naam of 'n simboliese skakel in 'n deur-gebruiker-skryfbare gids deurstap.
2. **Vervang daardie naam met 'n stadige pad**
- Skep die lang komponent- of gidsketting onder `\BaseNamedObjects` (of 'n ander skryfbare OM-wortel).
- Skep 'n simboliese skakel sodat die naam wat die kernel verwag nou na die stadige pad oplos. Jy kan die kwesbare driver se gids-opsoek na jou struktuur wys sonder om die oorspronklike teiken aan te raak.
3. **Trig die race**
- Thread A (slagoffer) voer die kwesbare kode uit en blokkeer binne die stadige opsoek.
- Thread B (aanvaller) skakel die beskermde toestand om (bv. ruil 'n file handle, herskryf 'n simboliese skakel, toggel object security) terwyl Thread A besig is.
- Wanneer Thread A hervat en die geprivilegieerde aksie uitvoer, sien dit verouderde toestand en voer die deur-aanvaller-beheerde operasie uit.
4. **Opruim** – Verwyder die gidsketting en simboliese skakels om te voorkom dat jy verdagte artefakte agterlaat of legitieme IPC-gebruikers breek.

## Operationele oorwegings

- **Combineer primitives** – Jy kan 'n lang naam *per vlak* in 'n gidsketting gebruik vir selfs hoër latensie totdat jy die `UNICODE_STRING` grootte uitput.
- **Eenmalige foute** – Die vergrote venster (tientalle mikrosekondes tot minute) maak “single trigger” foute realisties wanneer dit gekombineer word met CPU affinity pinning of hypervisor-assisted preemption.
- **Newe-effekte** – Die vertraging beïnvloed slegs die kwaadwillige pad, so die algehele stelselprestasie bly onaangeraak; verdedigers sal dit skaars opmerk tensy hulle namespace-groei monitor.
- **Opruim** – Hou handles na elke gids/object wat jy skep sodat jy daarna `NtMakeTemporaryObject`/`NtClose` kan oproep. Onbeperkte gidskettings kan andersins oor herstarts voortduur.
- **File-system races** – As die kwesbare pad uiteindelik deur NTFS oplos, kan jy 'n Oplock stapel (bv. `SetOpLock.exe` van dieselfde toolkit) op die agterliggende lêer plaas terwyl die OM-vertragingsloop hardloop, wat die verbruiker vir ekstra millisekondes vries sonder om die OM-graf te verander.

## Verdedigingsnotas

- Kernel-kode wat op named objects staatmaak, moet sekuriteitsgevoelige toestand *na* die open herbepaal, of 'n verwysing neem voor die kontrole (sodat die TOCTOU-gaping gesluit word).
- Handhaaf boonste grense op OM-paddiepte/-lengte voordat user-controlled name gedereferensieer word. Weiering van oortollig lange name dwing aanvallers terug in die mikrosekonde-venster.
- Instrumenteer object manager namespace-groei (ETW `Microsoft-Windows-Kernel-Object`) om verdagte duisende-komponente-kettings onder `\BaseNamedObjects` op te spoor.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
