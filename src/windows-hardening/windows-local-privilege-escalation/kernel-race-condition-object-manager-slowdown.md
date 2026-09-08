# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Waarom dit belangrik is om die race window te verleng

Baie Windows-kernel-LPE's volg die klassieke patroon `check_state(); NtOpenX("name"); privileged_action();`. Op moderne hardeware resolve 'n koue `NtOpenEvent`/`NtOpenSection` 'n kort naam in ongeveer 2 µs, wat byna geen tyd laat om die nagegane toestand te verander voordat die veilige aksie plaasvind nie. Deur die Object Manager Namespace (OMNS)-lookup in stap 2 doelbewus te dwing om tientalle mikrosekondes te duur, kry die aanvaller genoeg tyd om konsekwent races te wen wat andersins onbetroubaar sou wees, sonder dat duisende pogings nodig is.<sup>[[1]](#references)</sup>

## Object Manager lookup-internals in kort

* **OMNS-struktuur** – Name soos `\BaseNamedObjects\Foo` word gids vir gids opgelos. Elke komponent veroorsaak dat die kernel 'n *Object Directory* vind/open en Unicode-stringe vergelyk. Symbolic links (byvoorbeeld drive letters) kan onderweg gevolg word.
* **UNICODE_STRING-limiet** – OM-paaie word binne 'n `UNICODE_STRING` gedra waarvan `Length` 'n 16-bis-waarde is. Die absolute limiet is 65 535 grepe (32 767 UTF-16-kodepunte). Met prefixes soos `\BaseNamedObjects\` beheer 'n aanvaller steeds ongeveer 32 000 karakters.
* **Aanvaller-voorvereistes** – Enige gebruiker kan objects onder skryfbare gidse soos `\BaseNamedObjects` skep. Wanneer die kwesbare kode 'n naam daarbinne gebruik, of 'n symbolic link volg wat daar land, beheer die aanvaller die lookup-werkverrigting sonder spesiale privileges.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Single maximal component

Die koste om 'n komponent te resolve is ongeveer lineêr met sy lengte, omdat die kernel 'n Unicode-vergelyking teen elke entry in die ouergids moet uitvoer. Deur 'n event met 'n 32 kB-lange naam te skep, verhoog die `NtOpenEvent`-latency onmiddellik van ongeveer 2 µs na ongeveer 35 µs op Windows 11 24H2 (Snapdragon X Elite-toetsplatform).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktiese notas*

- Jy kan die lengtebeperking met enige benoemde kernel-object (events, sections, semaphores…) bereik.
- Symbolic links of reparse points kan 'n kort “victim”-naam na hierdie reuse komponent laat wys, sodat die slowdown deursigtig toegepas word.
- Omdat alles in namespaces wat deur die gebruiker geskryf kan word, bestaan, werk die payload vanaf 'n standaard user integrity level.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Diep rekursiewe gidse

'n Meer aggressiewe variant allokeer 'n ketting van duisende gidse (`\BaseNamedObjects\A\A\...\X`). Elke sprong aktiveer directory resolution-logika (ACL checks, hash lookups, reference counting), dus is die latency per vlak hoër as dié van 'n enkele string-vergelyking. Met ongeveer 16 000 vlakke (beperk deur dieselfde `UNICODE_STRING`-grootte) oorskry empiriese timings die 35 µs-grens wat deur lang enkele komponente bereik word.
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

* Wissel die karakter per vlak af (`A/B/C/...`) indien die ouergids duplikate begin verwerp.
* Hou ’n handle-skikking sodat jy die ketting ná exploitation netjies kan verwyder om te voorkom dat die namespace besoedel word.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minute in plaas van mikrosekondes)

Object directories ondersteun **shadow directories** (fallback lookups) en hash-tabelle met buckets vir entries. Misbruik albei, plus die limiet van 64-komponent symbolic-link reparses, om die slowdown te vermenigvuldig sonder om die `UNICODE_STRING`-lengte te oorskry:

1. Skep twee directories onder `\BaseNamedObjects`, byvoorbeeld `A` (shadow) en `A\A` (target). Skep die tweede een deur die eerste as die shadow directory te gebruik (`NtCreateDirectoryObjectEx`), sodat ontbrekende lookups in `A` na `A\A` deurval.
2. Vul elke directory met duisende **colliding names** wat in dieselfde hash bucket beland (byvoorbeeld deur die agterste syfers te verander terwyl dieselfde `RtlHashUnicodeString`-waarde behou word). Lookups verswak nou tot O(n)-lineêre scans binne ’n enkele directory.
3. Bou ’n ketting van ongeveer 63 **object manager symbolic links** wat herhaaldelik na die lang `A\A\…`-suffix reparse en die reparse-budget verbruik. Elke reparse begin parsing weer van bo af, wat die collision-koste vermenigvuldig.
4. Lookup van die finale component (`...\\0`) neem nou **minute** op Windows 11 wanneer 16 000 collisions per directory teenwoordig is, wat ’n feitlik gewaarborgde race win vir one-shot kernel LPEs bied.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Waarom dit belangrik is*: ’n verlangsaming van minute verander eenmalige race-gebaseerde LPEs in deterministiese exploits.<sup>[[1]](#references)</sup>

### 2025-hertoetsnotas en gereedgemaakte tooling

- James Forshaw het die technique met opgedateerde tydsberekeninge op Windows 11 24H2 (ARM64) herpubliseer. Baseline-opnames bly ongeveer 2 µs; ’n 32 kB-komponent verhoog dit tot ongeveer 35 µs, en shadow-dir + collision + 63-reparse-kettings bereik steeds ongeveer 3 minute, wat bevestig dat die primitives huidige builds oorleef. Bronkode en die perf-harnas is in die bygewerkte Project Zero-plasing.<sup>[[1]](#references)</sup>
- Jy kan opstelling met die publieke `symboliclink-testing-tools`-bundel script: `CreateObjectDirectory.exe` om die shadow/target-paar te skep en `NativeSymlink.exe` in ’n lus om die 63-hop-ketting te genereer. Dit vermy handgeskrewe `NtCreate*`-wrappers en hou ACLs konsekwent.<sup>[[2]](#references)</sup>

## Meting van jou race window

Bed jou exploit in met ’n vinnige harnas om te meet hoe groot die window op die slagoffer se hardeware word. Die snippet hieronder maak die teikenobjek `iterations` keer oop en gee die gemiddelde koste per opening terug met behulp van `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Die resultate vloei direk na jou race-orchestreringstrategie (byvoorbeeld die aantal worker threads wat benodig word, sleep-intervalle, en hoe vroeg jy die gedeelde toestand moet omskakel).

## Uitbuitingswerkvloei

1. **Vind die kwesbare open** – Volg die kernel-pad (via symbols, ETW, hypervisor tracing of reversing) totdat jy ’n `NtOpen*`/`ObOpenObjectByName`-aanroep vind wat ’n aanvaller-beheerde naam of ’n symbolic link in ’n user-writable directory deurloop.
2. **Vervang daardie naam met ’n stadige pad**
- Skep die lang komponent- of directory-ketting onder `\BaseNamedObjects` (of ’n ander writable OM-root).
- Skep ’n symbolic link sodat die naam wat die kernel verwag nou na die stadige pad resolve. Jy kan die kwesbare driver se directory lookup na jou struktuur wys sonder om aan die oorspronklike teiken te raak.
3. **Trigger die race**
- Thread A (victim) voer die kwesbare code uit en blokkeer binne die stadige lookup.
- Thread B (attacker) verander die guarded state (byvoorbeeld, ruil ’n file handle om, herskryf ’n symbolic link, of skakel object security) terwyl Thread A besig is.
- Wanneer Thread A hervat en die privileged action uitvoer, sien dit stale state en voer dit die attacker-controlled operation uit.
4. **Maak skoon** – Verwyder die directory-ketting en symbolic links om te voorkom dat verdagte artifacts agterbly of dat legitieme IPC-gebruikers ontwrig word.<sup>[[1]](#references)</sup>

## Toegepaste ketting: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), gepubliseer as ’n bypass vir RoguePlanet (CVE-2026-50656), demonstreer ’n breër exploitation pattern: laat ’n privileged scanner een voorstelling van ’n logiese file klassifiseer, en verander dan beide die bytes en namespace resolution voordat remediation dit gebruik. Die PoC kombineer ’n Cloud Files hydration TOCTOU, ’n Object Manager shadow-directory fallback, CLFS-generated-name capture en ’n local administrative-share link om Defender cleanup in ’n protected DLL write te omskep.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Vervang inhoud deur Cloud Files hydration

Registreer ’n attacker-writable directory as ’n Cloud Files sync root, koppel ’n `CF_CALLBACK_TYPE_FETCH_DATA` callback, en skep ’n placeholder waarvan die geadverteerde grootte ooreenstem met ’n deterministic detection trigger soos die EICAR ZIP. Die eerste fetch retourneer die trigger en verander callback state; latere fetches retourneer die payload. Nadat die scanner die eerste voorstelling geklassifiseer het, verkry die transfer key en herbegin hydration met payload-sized metadata, en forceer dan hydration tot EOF.<sup>[[4]](#references)</sup>
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
Die sekuriteitsgrens faal indien scan, verdict en remediation slegs na ’n padnaam of plekhouer-identiteit verwys: nie een waarborg dat ’n latere hydration die grepe teruggee wat geïnspekteer is nie.<sup>[[4]](#references)</sup>

### 2. Skakel ’n invariant path deur ’n shadow-directory fallback

Skep ’n teiken-Object Manager-directory en ’n tweede directory met `NtCreateDirectoryObjectEx`, en gee die teiken-handle as sy shadow/fallback-directory deur. Plaas ’n inskrywing met dieselfde naam, `WD_SCAN`, in albei resolusielae: die sigbare inskrywing wys na die normale working directory, terwyl die fallback-inskrywing na `\CLFS\??\<working-directory>` wys. Verskaf slegs die onderstaande invariant path aan Defender; deur die sigbare skakel te verwyder terwyl die operasie aktief is, val dieselfde string deur na die CLFS-gesteunde inskrywing.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Dit verskil daarvan om shadow directories slegs te gebruik om lookup te vertraag: die aanvaller verander die **betekenis** van ’n voorheen aanvaarde pad sonder om die string daarvan te wysig.<sup>[[4]](#references)</sup>

### 3. Vang die gegenereerde naam vas en installeer ’n lêernaam-spesifieke skakel

Monitor die werkgids met `ReadDirectoryChangesW`. Verwyder die sigbare `WD_SCAN`-skakel tydens die eerste `FILE_ACTION_ADDED` om fallback lookup te aktiveer. Vang die tweede gegenereerde lêernaam vas, open daardie CLFS-verwante lêer en sluit die reeks `0..MAXLONGLONG` met `LockFileEx`. Terwyl die bevoorregte bewerking gestuit word, vervang `WD_SCAN` in die sigbare gids met ’n werklike Object Manager-gids en skep ’n kind-simboliese skakel met ’n naam gebaseer op die waargenome lêernaam (die PoC verwyder die laaste vier karakters daarvan). Wys dit deur plaaslike SMB na die beskermde bestemming:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Die onbevoorregte proses kan nie self na daardie bestemming skryf nie, maar Defender se SYSTEM-konteks kan die loopback-administratiewe share deurkruis. Deur gegenereerde naamwaarneming met 'n lêernaam-spesifieke Object Manager-skakel te kombineer, hoef die remediation-artifact nie vooraf voorspel te word nie.<sup>[[4]](#references)</sup>

### 4. Stabiliseer die cleanup-race en aktiveer 'n bevoorregte loader

Voor skandering stoor die PoC 'n geldige PE (`ntdll.dll`) in die placeholder se `:stream` NTFS alternate data stream. Nadat redirection die beskermde basislêer skep, maak dit `phoneinfo.dll:stream` met execute-toegang oop en hou dit 'n `PAGE_EXECUTE_READ | SEC_IMAGE`-mapping lewendig terwyl cleanup voortgaan; die lewendige lêer-/section-objects beperk verwydering of vervanging tydens die finale race. Die herbeginne hydration gee nou die payload DLL eerder as EICAR terug, sodat die beskermde basislêer attacker-controlled code bevat.<sup>[[4]](#references)</sup>

'n Beskermde write word daarna in SYSTEM-execution omskep deur 'n vervaardigde `Report.wer` onder `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` te plaas en `\Microsoft\Windows\Windows Error Reporting\QueueReporting` deur die Task Scheduler COM API aan te roep. In hierdie chain laai bevoorregte WER-verwerking die geplante `C:\Windows\System32\phoneinfo.dll`; 'n named-pipe-verbinding word as die payload-execution-sein gebruik.<sup>[[4]](#references)</sup>

### Detection-pivots

Nuttige korrelasies is meer spesifiek as enige enkele tydelike lêernaam en dek alle namespace-oorgange in die chain:<sup>[[4]](#references)</sup>

- 'n Nuut-geregistreerde Cloud Files-provider, gevolg deur EICAR-detection en `CF_OPERATION_TYPE_RESTART_HYDRATION` op dieselfde placeholder.
- Object Manager-paaie wat `WD_TARGET_*`, `WD_SHADOW_*` of `WD_SCAN` bevat, veral 'n scan-pad onder `\\.\globalroot\BaseNamedObjects\Restricted\`.
- CLFS-lêerskepping, gevolg deur 'n eksklusiewe whole-file-lock en loopback-toegang tot `\\127.0.0.1\C$\Windows\System32\*.dll` vanaf 'n bevoorregte security process.
- Skepping van 'n System32 DLL saam met 'n NTFS ADS, gevolg deur `SEC_IMAGE`-mapping van die stream.
- 'n Attacker-created WER queue entry, gevolg deur 'n ongewone manual run van `\Microsoft\Windows\Windows Error Reporting\QueueReporting` en 'n image load van die geplante DLL.

## Toegepaste chain: oplock-gated mount-point switch teen bevoorregte remediation

'n Herbruikbare LPE-patroon verskyn wanneer 'n bevoorregte scanner 'n attacker-controlled file nagaan en dit later remediates deur die **pathname** te heropen eerder as om voort te gaan deur gevalideerde handles. FalconFlank is 'n publieke voorbeeld wat CrowdStrike Falcon se Office macro-removal workflow teiken; die repository beweer dat dit op Windows 11 25H2 en Windows Server 2025 met die relevante policy enabled getoets is, maar publiseer geen CVE, affected-build range, vendor advisory of patch status nie. Behandel die produkspesifieke bewering dus as onverifieerd en build-dependent.<sup>[[5]](#references)[[6]](#references)</sup>

### Race-uitleg

1. Bou 'n writable tree waarvan die finale relatiewe naam by die beoogde bestemming nuttig is. Die voorbeeld gebruik `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll`, maar skryf aanvanklik 'n OLE macro document—nie 'n PE DLL nie—na `bcrypt.dll`. Content-based detection trigger die remediation terwyl die attacker-controlled basename vir die latere side-load behoue bly.<sup>[[5]](#references)</sup>
2. Maak die directories met breë sharing en `FILE_OPEN_REPARSE_POINT` oop, en versoek daarna 'n asynchronous RH oplock op die trigger met `FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE` en `REQUEST_OPLOCK_INPUT_FLAG_REQUEST`. Wag vir die overlapped event en gebruik die voltooiing daarvan as die path-switch cue. 'n RH oplock-break notification is adviserende inligting eerder as bewys dat elke konflikterende operasie geblokkeer is; exploitability hang dus steeds van die victim se presiese open/remediation sequence af.<sup>[[5]](#references)[[7]](#references)</sup>
3. Verwyder ná die break die leaf directory met `FileDispositionInformationEx` (information class 64), met delete plus POSIX-semantics flags, maak sy handle toe en pas `IO_REPARSE_TAG_MOUNT_POINT` op die nou-leë parent toe met `FSCTL_SET_REPARSE_POINT_EX`. Die mount point redirect die onveranderde suffix na 'n protected tree soos `\\SystemRoot\\System32\\WindowsPowerShell`; die instelling van 'n reparse point faal as die directory nie leeg is nie, wat die voorafgaande deletion step verduidelik.<sup>[[5]](#references)[[8]](#references)</sup>
4. Hervat die bevoorregte workflow. As dit die string weer resolve sonder om te bewys dat die directory chain en finale object dieselfde is as dié wat voorheen geïnspekteer is, bereik dieselfde logiese pathname nou die attacker-selected protected directory. In die voorbeeld word sukses getoets deur `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` vanuit die oorspronklike proses read/write te heropen; dit onderskei die confused-deputy write primitive van die latere code-execution stage.<sup>[[5]](#references)</sup>
5. Vervang die gevolglike lêer met die werklike DLL en aktiveer 'n bevoorregte loader. Die PoC gebruik `CreateTransaction` + `CreateFileTransacted`, truncateer die lêer, map die DLL-sized replacement, kopieer die PE en commit; TxF bind die file handle en daaropvolgende handle-based operations aan die transaction, maar dit is 'n post-race replacement mechanism eerder as die bron van die privilege boundary failure.<sup>[[5]](#references)[[9]](#references)</sup>
6. Voer laastens 'n bestaande bevoorregte scheduled task uit waarvan die executable die geplante aangrensende filename ondersoek. FalconFlank roep `\\Microsoft\\Windows\\Application Experience\\MareBackup` aan, wag vir die DLL om aan `\\??\\pipe\\FALCONFLANK` te connect en verwyder dan die geplante lêer. Moenie 'n spesifieke resulting token uitsluitlik op grond van die task name aanvaar nie—verifieer die launched process, module path, integrity level en token op die getoetste build.<sup>[[5]](#references)</sup>

Die kern-auditvraag is dus nie “valideer die service die oorspronklike input path?” nie, maar “bly elke bevoorregte mutation gebind aan dieselfde geopende file- en directory-objects wat gevalideer is?” Deur handles tydens check en use te behou, child objects relatief tot 'n trusted directory handle te open, onverwagte reparse tags te verwerp en file identity voor mutation te herbevestig, word hierdie klas pathname-substitution bug gesluit.<sup>[[1]](#references)[[8]](#references)</sup>

### Detection en PoC-triage

High-signal detection korreleer die namespace-oorgang met die bevoorregte consumer: 'n OLE-header onder 'n DLL-basename in 'n GUID-named temporary tree, 'n oplock break, POSIX-style removal van die leaf directory, skepping van 'n mount point wat na 'n protected Windows-directory wys, en skepping of wysiging van dieselfde basename onder daardie bestemming. Voeg vir die publieke voorbeeld `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`, manual execution van `MareBackup` en die `FALCONFLANK` named pipe as nouer pivots by; geen enkele een is alleen voldoende nie.<sup>[[5]](#references)</sup>

Wanneer jy die PoC reproduseer, neem drie reliability defects in die gepubliseerde source in ag: dit roep `FlushFileBuffers` aan met die embedded byte-array pointer eerder as die file handle, toets 'n stale `HRESULT` ná `GetFolder`, `GetTask` en `Run`, en gebruik unbounded retry/wait loops vir directory deletion, reparse creation, die oplock event en pipe connection.<sup>[[5]](#references)</sup>

## Operasionele oorwegings

- **Combine primitives** – Jy kan 'n lang naam *per level* in 'n directory chain gebruik vir nog groter latency totdat jy die `UNICODE_STRING`-grootte uitput.
- **One-shot bugs** – Die vergrote window (tientalle mikrosekondes tot minute) maak “single trigger”-bugs realisties wanneer dit met CPU-affinity pinning of hypervisor-assisted preemption gekombineer word.
- **Side effects** – Die slowdown raak slegs die malicious path, dus bly algehele stelselwerkverrigting onaangeraak; defenders sal dit selde opmerk tensy hulle namespace growth monitor.
- **Cleanup** – Hou handles na elke directory/object wat jy skep sodat jy daarna `NtMakeTemporaryObject`/`NtClose` kan aanroep. Onbeperkte directory chains kan andersins oor reboots heen bly bestaan.
- **File-system races** – As die vulnerable path uiteindelik deur NTFS resolve, kan jy 'n Oplock (byvoorbeeld `SetOpLock.exe` uit dieselfde toolkit) op die backing file stack terwyl die OM slowdown loop. Dit vries die consumer vir addisionele millisekondes sonder om die OM graph te verander.<sup>[[2]](#references)</sup>

## Defensiewe notas

- Kernel-code wat op named objects staatmaak, behoort security-sensitive state *ná* die open weer te valideer, of 'n reference voor die check te neem (sodat die TOCTOU-gap gesluit word).
- Dwing upper bounds op OM path depth/length af voordat user-controlled names gedereferenceer word. Deur buitensporig lang name te verwerp, word attackers teruggedwing na die mikrosekonde-window.
- Instrumenteer Object Manager-namespace growth (ETW `Microsoft-Windows-Kernel-Object`) om verdagte chains met duisende komponente onder `\BaseNamedObjects` op te spoor.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Wen wedrenvoorwaardes met Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - Hoe om Transactional NTFS te gebruik](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
