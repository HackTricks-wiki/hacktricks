# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Waarom die race-venster uitrek saak maak

Baie Windows kernel LPEs volg die klassieke patroon `check_state(); NtOpenX("name"); privileged_action();`. Op moderne hardeware los 'n koue `NtOpenEvent`/`NtOpenSection` 'n kort naam op in ~2 µs, wat byna geen tyd laat om die gecheckte toestand om te draai voordat die veilige aksie plaasvind nie. Deur doelbewus die Object Manager Namespace (OMNS) lookup in stap 2 te laat duur tot enkele tientalle mikrosekondes, kry die aanvaller genoeg tyd om konsekwent andersins onbetroubare races te wen sonder om duisende pogings nodig te hê.

## Object Manager lookup internals in a nutshell

* **OMNS-struktuur** – Name soos `\BaseNamedObjects\Foo` word gids-vir-gids opgelos. Elke komponent veroorsaak dat die kernel 'n *Object Directory* vind/open en Unicode-stringe vergelyk. Simboliese skakels (bv. skyfletters) kan onderweg gevolg word.
* **UNICODE_STRING-limiet** – OM-paaie word in 'n `UNICODE_STRING` gedra waarvan `Length` 'n 16-bit waarde is. Die absolute limiet is 65 535 bytes (32 767 UTF-16 kodepunte). Met voorvoegsels soos `\BaseNamedObjects\`, beheer 'n aanvaller steeds ≈32 000 karakters.
* **Aanvaller-vereistes** – Enige gebruiker kan objekte skep onder skryfbare gidse soos `\BaseNamedObjects`. Wanneer die kwesbare kode 'n naam binne gebruik, of 'n simboliese skakel volg wat daar land, beheer die aanvaller die lookup-prestasies sonder enige spesiale voorregte.

## Slowdown primitive #1 – Single maximal component

Die koste om 'n komponent op te los is grofweg lineêr met sy lengte omdat die kernel 'n Unicode-vergelyking teen elke inskrywing in die ouergids moet uitvoer. Om 'n event te skep met 'n 32 kB-lange naam verhoog onmiddellik die `NtOpenEvent`-latensie van ~2 µs tot ~35 µs op Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktiese notas*

- Jy kan die lengtebeperking bereik deur enige benoemde kernel-objek te gebruik (events, sections, semaphores…).
- Symbolic links of reparse points kan 'n kort “victim” naam na hierdie reuse-komponent verwys sodat die vertraging deursigtig toegepas word.
- Aangesien alles in gebruikers-skryfbare namespaces leef, werk die payload vanaf 'n standaard gebruikersintegriteitsvlak.

## Vertragingsprimitief #2 – Diep rekursiewe gidse

'n Meer aggressiewe variant allokeer 'n ketting van duisende gidse (`\BaseNamedObjects\A\A\...\X`). Elke hop aktiveer gids-resolusielogika (ACL-kontroles, hash-opsoeke, verwysingtelling), so die latensie per vlak is hoër as by 'n enkele stringvergelyking. Met ~16 000 vlakke (beperk deur dieselfde `UNICODE_STRING` grootte) oorskry empiriese tydmetings die 35 µs-grens wat deur lang enkelkomponente bereik is.
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

* Wissel die karakter per vlak (`A/B/C/...`) as die ouer-gids begin duplikate te weier.
* Hou 'n handle array sodat jy die ketting skoon kan verwyder ná exploitation om te voorkom dat die namespace besoedel word.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minute in plaas van mikrosekondes)

Object directories ondersteun **shadow directories** (fallback lookups) en gebucketde hash-tabelle vir inskrywings. Misbruik albei plus die 64-komponent symbolic-link reparse limit om die vertraging te vermenigvuldig sonder om die `UNICODE_STRING` lengte te oorskry:

1. Skep twee gidse onder `\BaseNamedObjects`, bv. `A` (shadow) en `A\A` (target). Skep die tweede deur die eerste as die shadow directory te gebruik (`NtCreateDirectoryObjectEx`), sodat ontbrekende lookups in `A` deurval na `A\A`.
2. Vul elke gids met duisende **colliding names** wat in dieselfde hash-bucket land (bv. deur agterste syfers te varieer terwyl dieselfde `RtlHashUnicodeString` waarde behou word). Lookups degradeer nou na O(n) lineêre skanderings binne 'n enkele gids.
3. Bou 'n ketting van ~63 **object manager symbolic links** wat herhaaldelik herparse na die lang `A\A\…` agtervoegsel, en sodoende die reparse-begroting opbruik. Elke reparse begin parsing weer van bo af, wat die botsingskoste vermeerder.
4. Die lookup van die finale komponent (`...\\0`) neem nou **minute** op Windows 11 wanneer 16 000 botsings per gids teenwoordig is, wat 'n prakties gewaarborgde race-wen verskaf vir one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Waarom dit saak maak*: 'n minute-lange vertraging verander one-shot race-based LPEs in deterministic exploits.

## Meet jou race-venster

Voeg 'n vinnige toetsharnas in jou exploit in om te meet hoe groot die venster op die slagoffer se hardware word. Die onderstaande kodefragment open die teikenobjek `iterations` keer en gee die gemiddelde koste per open terug met behulp van `QueryPerformanceCounter`.
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
Die resultate voed direk in jou race orchestration strategy in (bv. aantal werkerdrade benodig, slaappouse, hoe vroeg jy die gedeelde toestand moet omskakel).

## Uitbuitingswerkvloei

1. **Locate the vulnerable open** – Trace die kernel-pad (via symbols, ETW, hypervisor tracing, or reversing) totdat jy 'n `NtOpen*`/`ObOpenObjectByName` oproep vind wat 'n aanvaller-beheerde naam of 'n simboliese skakel in 'n user-writable directory deurloop.
2. **Replace that name with a slow path**
- Skep die lang komponent- of gidsketting onder `\BaseNamedObjects` (of another writable OM root).
- Skep 'n simboliese skakel sodat die naam wat die kernel verwag nou na die slow path oplos. Jy kan die kwetsbare driver se directory lookup na jou struktuur wys sonder om die oorspronklike teiken aan te raak.
3. **Trigger the race**
- Thread A (slagoffer) voer die kwetsbare kode uit en blokkeer in die stadige opsoektog.
- Thread B (aanvaller) verander die beskermde toestand (bv. ruil 'n lêerhandvatsel, herskryf 'n simboliese skakel, skakel voorwerp-sekuriteit om) terwyl Thread A besig is.
- Wanneer Thread A hervat en die bevoegde aksie uitvoer, merk dit die verouderde toestand en voer die deur die aanvaller beheerste operasie uit.
4. **Clean up** – Verwyder die gidsketting en simboliese skakels om te voorkom dat jy verdagte artefakte agterlaat of wettige IPC-gebruikers se werking breek.

## Operasionele oorwegings

- **Combine primitives** – Jy kan 'n lang naam *per level* in 'n gidsketting gebruik vir selfs hoër latensie totdat jy die `UNICODE_STRING` grootte uitput.
- **One-shot bugs** – Die vergrote venster (tientalle mikrosekondes tot minute) maak “single trigger” bugs realisties wanneer dit gepaard gaan met CPU affinity pinning of hypervisor-assisted preemption.
- **Side effects** – Die vertraag beïnvloed slegs die kwaadwillige pad, sodat die algehele stelselprestasie onaangeraak bly; verdedigers sal selde iets opmerk tensy hulle naamruimte-groei monitor.
- **Cleanup** – Hou handles na elke gids/voorwerp wat jy skep sodat jy later `NtMakeTemporaryObject`/`NtClose` kan aanroep. Onbeperkte gidskettings kan andersins oor herstarts voortduur.

## Verdedigende notas

- Kernel-kode wat staatmaak op named objects moet sekuriteitsgevoelige toestand *na* die open hervalideer, of 'n verwysing neem voor die kontrole (om die TOCTOU-gaping te sluit).
- Handhaaf boonste perke op OM-paddiepte/-lengte voordat gebruikersbeheerde name gedereferensieer word. Om oorlang name te weier dwing aanvallers terug in die mikrosekonde-venster.
- Instrumenteer die object manager naamruimte-groei (ETW `Microsoft-Windows-Kernel-Object`) om verdagte kettings met duisende komponente onder `\BaseNamedObjects` te bespeur.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
