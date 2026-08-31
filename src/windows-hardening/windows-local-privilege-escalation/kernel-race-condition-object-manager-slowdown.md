# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Waarom dit belangrik is om die race window uit te rek

Baie Windows-kernel-LPE's volg die klassieke patroon `check_state(); NtOpenX("name"); privileged_action();`. Op moderne hardeware los 'n koue `NtOpenEvent`/`NtOpenSection` 'n kort naam in ~2 µs op, wat byna geen tyd laat om die nagegane toestand om te skakel voordat die veilige aksie plaasvind nie. Deur die Object Manager Namespace (OMNS)-opsoek in stap 2 doelbewus tien-derduisende mikrosekondes te laat duur, kry die aanvaller genoeg tyd om konsekwent races te wen wat andersins onbetroubaar sou wees, sonder dat duisende pogings nodig is.<sup>[[1]](#references)</sup>

## Object Manager-opsoekinternals in 'n neutedop

* **OMNS-struktuur** – Name soos `\BaseNamedObjects\Foo` word gids vir gids opgelos. Elke komponent veroorsaak dat die kernel 'n *Object Directory* vind/ope en Unicode-stringe vergelyk. Symbolic links (byvoorbeeld dryfletters) kan onderweg gevolg word.
* **UNICODE_STRING-limiet** – OM-paaie word binne 'n `UNICODE_STRING` gedra waarvan `Length` 'n 16-bis-waarde is. Die absolute limiet is 65 535 grepe (32 767 UTF-16-kodepunte). Met voorvoegsels soos `\BaseNamedObjects\` beheer 'n aanvaller steeds ongeveer 32 000 karakters.
* **Aanvaller-voorvereistes** – Enige gebruiker kan objekte onder skryfbare gidse soos `\BaseNamedObjects` skep. Wanneer die kwesbare kode 'n naam binne een gebruik, of 'n symbolic link volg wat daar land, beheer die aanvaller die opsoekwerkverrigting sonder spesiale voorregte.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Enkel maksimumkomponent

Die koste om 'n komponent op te los is rofweg lineêr met sy lengte, omdat die kernel 'n Unicode-vergelyking teen elke inskrywing in die ouergids moet uitvoer. Deur 'n event met 'n naam van 32 kB te skep, verhoog die `NtOpenEvent`-latensie onmiddellik van ~2 µs tot ~35 µs op Windows 11 24H2 (Snapdragon X Elite-toetsplatform).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktiese notas*

- Jy kan die lengtelimiet bereik deur enige named kernel object te gebruik (events, sections, semaphores…).
- Symbolic links of reparse points kan ’n kort “victim”-naam na hierdie reuse-komponent laat wys, sodat die slowdown deursigtig toegepas word.
- Omdat alles in user-writable namespaces leef, werk die payload vanaf ’n standaard gebruikersintegriteitsvlak.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Diep rekursiewe gidse

’n Meer aggressiewe variant allokeer ’n ketting van duisende gidse (`\BaseNamedObjects\A\A\...\X`). Elke sprong aktiveer directory resolution-logika (ACL-checks, hash lookups, reference counting), dus is die latency per vlak hoër as dié van ’n enkele string-vergelyking. Met ~16 000 vlakke (beperk deur dieselfde `UNICODE_STRING`-grootte) oorskry empiriese metings die 35 µs-grens wat deur lang enkelkomponente bereik word.
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

* Wissel die karakter per vlak (`A/B/C/...`) af as die ouergids duplikate begin verwerp.
* Hou ’n handvatsel-skikking sodat jy die ketting ná exploitation netjies kan verwyder om te voorkom dat die namespace besoedel word.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minute in plaas van mikrosekondes)

Object directories ondersteun **shadow directories** (fallback lookups) en hash tables met buckets vir entries. Misbruik albei, plus die 64-komponent symbolic-link reparse-limiet, om slowdown te vermenigvuldig sonder om die `UNICODE_STRING`-lengte te oorskry:

1. Skep twee directories onder `\BaseNamedObjects`, byvoorbeeld `A` (shadow) en `A\A` (target). Skep die tweede een met die eerste as die shadow directory (`NtCreateDirectoryObjectEx`), sodat ontbrekende lookups in `A` na `A\A` deurval.
2. Vul elke directory met duisende **colliding names** wat in dieselfde hash bucket land (byvoorbeeld deur trailing digits te wissel terwyl dieselfde `RtlHashUnicodeString`-waarde behou word). Lookups verswak nou tot O(n) lineêre scans binne ’n enkele directory.
3. Bou ’n ketting van ongeveer 63 **object manager symbolic links** wat herhaaldelik na die lang `A\A\…`-suffix herparse, en sodoende die reparse-begroting verbruik. Elke reparse begin parsing van bo af, wat die collision-koste vermenigvuldig.
4. Lookup van die finale komponent (`...\\0`) neem nou **minute** op Windows 11 wanneer 16 000 collisions per directory teenwoordig is, wat ’n prakties gewaarborgde race win vir one-shot kernel LPEs bied.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Waarom dit saak maak*: ’n Verlangsaming van etlike minute verander eenmalige race-gebaseerde LPEs in deterministiese exploits.<sup>[[1]](#references)</sup>

### 2025-hertoetsnotas en gereedgemaakte tooling

- James Forshaw het die tegniek met opgedateerde tydsberekeninge op Windows 11 24H2 (ARM64) herpubliseer. Baseline opens bly ongeveer 2 µs; ’n 32 kB-komponent verhoog dit tot ongeveer 35 µs, en shadow-dir + collision + 63-reparse chains bereik steeds ongeveer 3 minute, wat bevestig dat die primitives huidige builds oorleef. Source code en die perf harness is in die opgedateerde Project Zero-plasing beskikbaar.<sup>[[1]](#references)</sup>
- Jy kan die opstelling met die publieke `symboliclink-testing-tools`-bundel script: `CreateObjectDirectory.exe` om die shadow/target-paar te skep en `NativeSymlink.exe` in ’n loop om die 63-hop chain te genereer. Dit vermy handgeskrewe `NtCreate*`-wrappers en hou ACLs konsekwent.<sup>[[2]](#references)</sup>

## Meting van jou race window

Embed ’n vinnige harness binne jou exploit om te meet hoe groot die window op die slagoffer se hardeware word. Die snippet hieronder open die target object `iterations` keer en gee die gemiddelde koste per open terug met behulp van `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Die resultate vloei direk in jou race-orchestration-strategie in (bv. die aantal worker threads wat benodig word, sleep intervals, en hoe vroeg jy die gedeelde toestand moet omskakel).

## Exploitation-werkvloei

1. **Vind die kwesbare opening** – Volg die kernel-pad (via simbole, ETW, hypervisor tracing of reversing) totdat jy ’n `NtOpen*`/`ObOpenObjectByName`-aanroep vind wat ’n aanvaller-beheerde naam of ’n symbolic link in ’n user-writable gids deurloop.
2. **Vervang daardie naam met ’n slow path**
- Skep die lang komponent of gidsketting onder `\BaseNamedObjects` (of ’n ander writable OM-root).
- Skep ’n symbolic link sodat die naam wat die kernel verwag, nou na die slow path resolve. Jy kan die kwesbare driver se directory lookup na jou struktuur wys sonder om aan die oorspronklike teiken te raak.
3. **Trigger die race**
- Thread A (slagoffer) voer die kwesbare kode uit en blokkeer binne die slow lookup.
- Thread B (aanvaller) skakel die bewaakte toestand om (bv. ruil ’n file handle om, herskryf ’n symbolic link, of wissel object security) terwyl Thread A besig gehou word.
- Wanneer Thread A hervat en die bevoorregte aksie uitvoer, sien dit verouderde toestand en voer dit die aanvaller-beheerde operasie uit.
4. **Maak skoon** – Verwyder die gidsketting en symbolic links om te voorkom dat verdagte artefakte agterbly of dat wettige IPC-gebruikers ontwrig word.<sup>[[1]](#references)</sup>

## Toegepaste ketting: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), gepubliseer as ’n bypass vir RoguePlanet (CVE-2026-50656), demonstreer ’n breër exploitation-patroon: laat ’n bevoorregte scanner een voorstelling van ’n logiese lêer klassifiseer, en verander dan beide sy bytes en namespace resolution voordat remediation dit gebruik. Die PoC kombineer ’n Cloud Files hydration TOCTOU, ’n Object Manager shadow-directory fallback, CLFS-generated-name capture, en ’n local administrative-share link om Defender cleanup in ’n protected DLL write te omskep.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Vervang inhoud deur Cloud Files hydration

Registreer ’n attacker-writable gids as ’n Cloud Files sync root, koppel ’n `CF_CALLBACK_TYPE_FETCH_DATA`-callback, en skep ’n placeholder waarvan die geadverteerde grootte ooreenstem met ’n deterministiese detection trigger soos die EICAR ZIP. Die eerste fetch stuur die trigger terug en skakel callback state om; latere fetches stuur die payload terug. Nadat die scanner die eerste voorstelling geklassifiseer het, verkry die transfer key en herbegin hydration met payload-sized metadata, en forseer dan hydration tot EOF.<sup>[[4]](#references)</sup>
```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```
Die sekuriteitsgrens faal indien skandering, beslissing en remediëring slegs na 'n padnaam of plekhoueridentiteit verwys: nie een waarborg dat 'n latere hydration die grepe teruggee wat geïnspekteer is nie.<sup>[[4]](#references)</sup>

### 2. Skakel 'n invariansiepad deur 'n shadow-directory fallback

Skep 'n Object Manager-directory vir die teiken en 'n tweede directory met `NtCreateDirectoryObjectEx`, en gee die teiken-handle as sy shadow/fallback-directory deur. Plaas 'n inskrywing met dieselfde naam, `WD_SCAN`, in albei resolusielae: die sigbare inskrywing wys na die normale werksdirectory, terwyl die fallback-inskrywing na `\CLFS\??\<working-directory>` wys. Verskaf slegs die invariansiepad hieronder aan Defender; deur die sigbare skakel te verwyder terwyl die bewerking aktief is, val dieselfde string deur na die CLFS-gesteunde inskrywing.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Dit verskil van die gebruik van shadow directories slegs om lookup te vertraag: die aanvaller verander die **betekenis** van ’n voorheen aanvaarbare pad sonder om die string daarvan te wysig.<sup>[[4]](#references)</sup>

### 3. Vang die gegenereerde naam vas en installeer ’n lêernaamspesifieke skakel

Monitor die werkgids met `ReadDirectoryChangesW`. Verwyder die sigbare `WD_SCAN`-skakel met die eerste `FILE_ACTION_ADDED` om fallback-lookup te aktiveer. Vang die tweede gegenereerde lêernaam vas, open daardie CLFS-verwante lêer en sluit die reeks `0..MAXLONGLONG` met `LockFileEx`. Terwyl die bevoorregte operasie gestuit word, vervang `WD_SCAN` in die sigbare gids met ’n werklike Object Manager-gids en skep ’n kind-simboliese skakel met die waargenome lêernaam as naam (die PoC verwyder die laaste vier karakters daarvan). Wys dit via plaaslike SMB na die beskermde bestemming:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Die onbevoorregte proses kan nie self na daardie bestemming skryf nie, maar Defender se SYSTEM-konteks kan die loopback-administratiewe share deurkruis. Deur gegenereerde-name-waarneming met 'n lêernaamspesifieke Object Manager-skakel te kombineer, hoef die remediation-artifact nie vooraf voorspel te word nie.<sup>[[4]](#references)</sup>

### 4. Stabiliseer die cleanup-race en aktiveer 'n bevoorregte loader

Voordat die skandering begin, stoor die PoC 'n geldige PE (`ntdll.dll`) in die placeholder se `:stream` NTFS alternate data stream. Nadat redirection die beskermde basislêer skep, maak dit `phoneinfo.dll:stream` oop met execute-toegang en hou dit 'n `PAGE_EXECUTE_READ | SEC_IMAGE`-mapping aktief terwyl cleanup voortgaan; die aktiewe file/section-objekte beperk deletion of replacement tydens die finale race. Die herbeginne hydration gee nou die payload DLL in plaas van EICAR terug, dus bevat die beskermde basislêer attacker-controlled code.<sup>[[4]](#references)</sup>

'n Beskermde write word daarna in SYSTEM-execution omskep deur 'n crafted `Report.wer` onder `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` te plaas en `\Microsoft\Windows\Windows Error Reporting\QueueReporting` deur die Task Scheduler COM API aan te roep. In hierdie chain laai bevoorregte WER-verwerking die geplante `C:\Windows\System32\phoneinfo.dll`; 'n named-pipe-verbinding word as die payload execution-signal gebruik.<sup>[[4]](#references)</sup>

### Opsporingspunte

Nuttige korrelasies is meer spesifiek as enige enkele temporary filename en dek alle namespace-oorgange in die chain:<sup>[[4]](#references)</sup>

- 'n Nuutgeregistreerde Cloud Files-provider gevolg deur EICAR-detection en `CF_OPERATION_TYPE_RESTART_HYDRATION` op dieselfde placeholder.
- Object Manager-paaie wat `WD_TARGET_*`, `WD_SHADOW_*` of `WD_SCAN` bevat, veral 'n scan path onder `\\.\globalroot\BaseNamedObjects\Restricted\`.
- CLFS-lêerskepping gevolg deur 'n eksklusiewe whole-file lock en loopback-toegang tot `\\127.0.0.1\C$\Windows\System32\*.dll` vanaf 'n bevoorregte security process.
- Skepping van 'n System32-DLL saam met 'n NTFS ADS, gevolg deur `SEC_IMAGE`-mapping van die stream.
- 'n Attacker-created WER queue entry gevolg deur 'n ongewone manual run van `\Microsoft\Windows\Windows Error Reporting\QueueReporting` en 'n image load van die geplante DLL.

## Operasionele oorwegings

- **Combine primitives** – Jy kan 'n lang naam *per level* in 'n directory chain gebruik vir selfs hoër latency totdat jy die `UNICODE_STRING`-grootte uitput.
- **One-shot bugs** – Die uitgebreide window (tientalle mikrosekondes tot minute) maak “single trigger”-bugs realisties wanneer dit met CPU-affinity-pinning of hypervisor-assisted preemption gekombineer word.
- **Side effects** – Die slowdown beïnvloed slegs die malicious path, dus bly algehele stelselwerkverrigting onaangetas; defenders sal dit selde opmerk tensy hulle namespace-groei monitor.
- **Cleanup** – Hou handles na elke directory/object wat jy skep sodat jy daarna `NtMakeTemporaryObject`/`NtClose` kan aanroep. Onbeperkte directory chains kan andersins oor reboots heen voortbestaan.
- **File-system races** – As die vulnerable path uiteindelik deur NTFS resolve, kan jy 'n Oplock (byvoorbeeld `SetOpLock.exe` uit dieselfde toolkit) op die backing file stack terwyl die OM-slowdown loop, wat die consumer vir bykomende millisekondes vries sonder om die OM graph te wysig.<sup>[[2]](#references)</sup>

## Defensiewe notas

- Kernel code wat op named objects steun, moet security-sensitive state *ná* die open herbevestig, of 'n reference vóór die check neem (om die TOCTOU-gap te sluit).
- Dwing upper bounds op OM path depth/length af voordat user-controlled names gedereferenceer word. Die weiering van buitensporig lang name dwing attackers terug na die mikrosekonde-window.
- Instrumenteer Object Manager-namespace-groei (ETW `Microsoft-Windows-Kernel-Object`) om verdagte chains met duisende komponente onder `\BaseNamedObjects` op te spoor.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Wen van Race Conditions met Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
