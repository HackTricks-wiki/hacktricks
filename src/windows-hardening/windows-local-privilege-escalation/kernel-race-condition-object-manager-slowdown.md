# Exploitation ya Kernel Race Condition kupitia Slow Paths za Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Kwa nini kuongeza race window ni muhimu

LPE nyingi za Windows hufuata muundo wa kawaida `check_state(); NtOpenX("name"); privileged_action();`. Kwenye hardware ya kisasa, `NtOpenEvent`/`NtOpenSection` ya kwanza hutatua jina fupi kwa takriban 2 µs, hivyo kubaki na muda mdogo sana wa kubadilisha hali iliyokaguliwa kabla ya secure action kutekelezwa. Kwa kulazimisha kwa makusudi utafutaji wa Object Manager Namespace (OMNS) katika hatua ya 2 kuchukua makumi ya microseconds, attacker hupata muda wa kutosha kushinda race ambazo vinginevyo zingekuwa zisizoaminika, bila kuhitaji majaribio ya maelfu.<sup>[[1]](#references)</sup>

## Muhtasari wa internals za Object Manager lookup

* **Muundo wa OMNS** – Majina kama `\BaseNamedObjects\Foo` hutatuliwa directory baada ya directory. Kila component husababisha kernel kutafuta/kufungua *Object Directory* na kulinganisha Unicode strings. Symbolic links (kwa mfano, drive letters) zinaweza kufuatwa njiani.
* **Kikomo cha UNICODE_STRING** – Njia za OM hubebwa ndani ya `UNICODE_STRING` ambayo `Length` yake ni thamani ya biti 16. Kikomo cha juu kabisa ni baiti 65 535 (codepoints 32 767 za UTF-16). Ikiwa kuna prefixes kama `\BaseNamedObjects\`, attacker bado hudhibiti takriban herufi 32 000.
* **Masharti ya attacker** – Mtumiaji yeyote anaweza kuunda objects ndani ya directories zinazoandikika kama `\BaseNamedObjects`. Wakati vulnerable code inapotumia jina lililo ndani yake, au kufuata symbolic link inayoishia hapo, attacker hudhibiti utendaji wa lookup bila special privileges.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Component moja yenye urefu wa juu zaidi

Gharama ya kutatua component huwa takriban linear kulingana na urefu wake kwa sababu kernel lazima ifanye Unicode comparison dhidi ya kila entry kwenye parent directory. Kuunda event yenye jina lenye urefu wa 32 kB huongeza mara moja latency ya `NtOpenEvent` kutoka ~2 µs hadi ~35 µs kwenye Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Maelezo ya vitendo*

- Unaweza kufikia kikomo cha urefu ukitumia kernel object yoyote iliyopewa jina (events, sections, semaphores…).
- Symbolic links au reparse points zinaweza kuelekeza jina fupi la “victim” kwenye component hii kubwa, hivyo slowdown kutekelezwa kwa uwazi.
- Kwa kuwa kila kitu kinaishi katika namespaces zinazoweza kuandikwa na user, payload hufanya kazi kutoka kiwango cha kawaida cha user integrity.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Saraka zinazojirudia kwa kina

Toleo lenye ukali zaidi hutenga mlolongo wa maelfu ya saraka (`\BaseNamedObjects\A\A\...\X`). Kila hop huanzisha directory resolution logic (ACL checks, hash lookups, reference counting), kwa hiyo latency ya kila level ni kubwa kuliko ya kulinganisha string moja. Kwa takriban viwango 16 000 (vinavyowekewa kikomo na ukubwa huohuo wa `UNICODE_STRING`), vipimo vya majaribio huzidi kizingiti cha 35 µs kilichofikiwa na components ndefu za pekee.
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
Vidokezo:

* Badilisha character kwa kila level (`A/B/C/...`) ikiwa parent directory inaanza kukataa duplicates.
* Weka handle array ili uweze kufuta chain kwa usafi baada ya exploitation na kuepuka kuchafua namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (dakika badala ya microseconds)

Object directories zinaunga mkono **shadow directories** (fallback lookups) na hash tables zenye buckets kwa entries. Tumia vibaya vyote viwili pamoja na kikomo cha 64-component symbolic-link reparse ili kuzidisha slowdown bila kuzidi urefu wa `UNICODE_STRING`:

1. Unda directories mbili chini ya `\BaseNamedObjects`, kwa mfano `A` (shadow) na `A\A` (target). Unda ya pili ukitumia ya kwanza kama shadow directory (`NtCreateDirectoryObjectEx`), ili lookups zinazokosekana katika `A` zipitie hadi `A\A`.
2. Jaza kila directory kwa maelfu ya **colliding names** zinazoangukia kwenye hash bucket moja (kwa mfano, badilisha trailing digits huku ukihifadhi thamani ileile ya `RtlHashUnicodeString`). Lookups sasa hushuka hadi linear scans za O(n) ndani ya directory moja.
3. Jenga chain ya takriban **63 object manager symbolic links** ambazo mara kwa mara hufanya reparse kuingia kwenye suffix ndefu ya `A\A\…`, zikitumia reparse budget. Kila reparse huanzisha tena parsing kutoka juu, na hivyo kuzidisha collision cost.
4. Lookup ya final component (`...\\0`) sasa huchukua **dakika** kwenye Windows 11 wakati kuna collisions 16,000 kwa kila directory, na kutoa ushindi wa race unaokaribia kuhakikishwa kwa one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Kwa nini ni muhimu*: Kupungua kwa kasi kwa muda wa dakika kadhaa hubadilisha LPE za race-based za jaribio moja kuwa exploits za deterministic.<sup>[[1]](#references)</sup>

### Maelezo ya retest ya 2025 na tooling iliyo tayari kutumika

- James Forshaw alichapisha tena technique hii ikiwa na timings zilizosasishwa kwenye Windows 11 24H2 (ARM64). Baseline opens bado ni ~2 µs; component ya 32 kB huongeza hii hadi ~35 µs, na shadow-dir + collision + minyororo ya 63-reparse bado hufikia ~dakika 3, jambo linalothibitisha kuwa primitives zinaendelea kufanya kazi kwenye builds za sasa. Source code na perf harness ziko kwenye Project Zero post iliyosasishwa.<sup>[[1]](#references)</sup>
- Unaweza kuscript setup ukitumia bundle ya public `symboliclink-testing-tools`: `CreateObjectDirectory.exe` kuanzisha shadow/target pair na `NativeSymlink.exe` kwenye loop ili kutoa chain ya hops 63. Hii huepuka wrappers za `NtCreate*` zilizoandikwa kwa mkono na hudumisha ACLs kwa uthabiti.<sup>[[2]](#references)</sup>

## Kupima race window yako

Embed harness fupi ndani ya exploit yako ili kupima ukubwa wa window kwenye hardware ya victim. Snippet iliyo hapa chini hufungua target object mara `iterations` na kurudisha gharama ya wastani ya kila open kwa kutumia `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Matokeo huingia moja kwa moja katika mkakati wako wa race orchestration (kwa mfano, idadi ya worker threads zinazohitajika, vipindi vya sleep, na jinsi unavyohitaji kubadilisha shared state mapema).

## Workflow ya exploitation

1. **Tambua open iliyo hatarini** – Fuatilia kernel path (kupitia symbols, ETW, hypervisor tracing, au reversing) hadi upate call ya `NtOpen*`/`ObOpenObjectByName` inayopitia jina linalodhibitiwa na attacker au symbolic link katika user-writable directory.
2. **Badilisha jina hilo kwa slow path**
- Unda long component au directory chain chini ya `\BaseNamedObjects` (au OM root nyingine inayoweza kuandikwa).
- Unda symbolic link ili jina linalotarajiwa na kernel sasa lielekeze kwenye slow path. Unaweza kuelekeza vulnerable driver’s directory lookup kwenye muundo wako bila kugusa original target.
3. **Trigger race**
- Thread A (victim) hutekeleza code iliyo hatarini na kuzuiwa ndani ya slow lookup.
- Thread B (attacker) hubadilisha guarded state (kwa mfano, hubadilisha file handle, huandika upya symbolic link, au hubadilisha object security) huku Thread A ikiwa busy.
- Thread A inapoendelea na kutekeleza privileged action, huona stale state na kutekeleza attacker-controlled operation.
4. **Safisha** – Futa directory chain na symbolic links ili kuepuka kuacha suspicious artifacts au kuvuruga legitimate IPC users.<sup>[[1]](#references)</sup>

## Applied chain: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), iliyochapishwa kama bypass ya RoguePlanet (CVE-2026-50656), inaonyesha exploitation pattern pana zaidi: fanya privileged scanner iainishe representation moja ya logical file, kisha ubadilishe bytes zake na namespace resolution kabla remediation haijaitumia. PoC inaunganisha Cloud Files hydration TOCTOU, Object Manager shadow-directory fallback, CLFS-generated-name capture, na local administrative-share link ili kubadilisha Defender cleanup kuwa protected DLL write.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Substitute content kupitia Cloud Files hydration

Sajili directory inayoweza kuandikwa na attacker kama Cloud Files sync root, unganisha `CF_CALLBACK_TYPE_FETCH_DATA` callback, na unda placeholder ambayo advertised size yake inalingana na deterministic detection trigger kama vile EICAR ZIP. Fetch ya kwanza hurejesha trigger na kubadilisha callback state; fetch zinazofuata hurejesha payload. Baada ya scanner kuainisha representation ya kwanza, pata transfer key na uanze upya hydration ukiwa na payload-sized metadata, kisha forcing hydration hadi EOF.<sup>[[4]](#references)</sup>
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
Mpaka wa usalama hushindwa ikiwa scan, verdict, na remediation zinarejelea tu pathname au utambulisho wa placeholder: hakuna kati yake inayohakikisha kwamba hydration ya baadaye inarejesha bytes zilizokaguliwa.<sup>[[4]](#references)</sup>

### 2. Badilisha invariant path kupitia shadow-directory fallback

Unda saraka ya Object Manager inayolengwa na saraka ya pili ukitumia `NtCreateDirectoryObjectEx`, ukipitisha handle ya lengo kama saraka yake ya shadow/fallback. Weka ingizo la `WD_SCAN` lenye jina sawa katika tabaka zote mbili za resolution: ingizo linaloonekana lielekeze kwenye working directory ya kawaida, huku ingizo la fallback likielekeze kwenye `\CLFS\??\<working-directory>`. Mpe Defender invariant path iliyo hapa chini pekee; kufuta link inayoonekana wakati operesheni inaendelea husababisha string hiyo hiyo kupita kwenye ingizo linaloungwa mkono na CLFS.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Hii ni tofauti na kutumia shadow directories pekee ili kupunguza kasi ya utafutaji: mshambulizi hubadilisha **maana** ya path iliyokubaliwa hapo awali bila kubadilisha string yake.<sup>[[4]](#references)</sup>

### 3. Nasa jina lililotengenezwa na usakinishe link mahususi kwa filename

Fuatilia working directory kwa kutumia `ReadDirectoryChangesW`. Kwenye `FILE_ACTION_ADDED` ya kwanza, ondoa link ya `WD_SCAN` inayoonekana ili kuamilisha fallback lookup. Nasa filename ya pili iliyotengenezwa, fungua faili hiyo inayohusiana na CLFS, na funga range ya `0..MAXLONGLONG` kwa kutumia `LockFileEx`. Operesheni ya privileged ikiwa imesimama, badilisha `WD_SCAN` katika directory inayoonekana na iwe Object Manager directory halisi, kisha unda child symbolic link iliyopewa jina kutokana na filename iliyotambuliwa (PoC huondoa herufi zake nne za mwisho). Ielekeze kwenye destination iliyolindwa kupitia local SMB:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Mchakato usio na privileges hauwezi kuandika lengwa hilo moja kwa moja, lakini muktadha wa SYSTEM wa Defender unaweza kupitia loopback administrative share. Kuchanganya uangalizi wa majina yanayotengenezwa na Object Manager link maalum kwa filename kunaondoa ulazima wa kutabiri artifact ya remediation mapema.<sup>[[4]](#references)</sup>

### 4. Imarisha cleanup race na uanzishe privileged loader

Kabla ya scanning, PoC huhifadhi PE halali (`ntdll.dll`) katika NTFS alternate data stream ya `:stream` ya placeholder. Baada ya redirection kuunda protected base file, hufungua `phoneinfo.dll:stream` kwa execute access na kudumisha mapping ya `PAGE_EXECUTE_READ | SEC_IMAGE` ikiwa hai wakati cleanup ikiendelea; file/section objects zilizo hai huzuia deletion au replacement wakati wa race ya mwisho. Hydration iliyoanzishwa upya sasa hurejesha payload DLL badala ya EICAR, hivyo protected base file huwa na code inayodhibitiwa na attacker.<sup>[[4]](#references)</sup>

Protected write hubadilishwa kuwa SYSTEM execution kwa kuweka `Report.wer` iliyoundwa mahususi chini ya `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` na kuinvoke `\Microsoft\Windows\Windows Error Reporting\QueueReporting` kupitia Task Scheduler COM API. Katika chain hii, privileged WER processing hupakia `C:\Windows\System32\phoneinfo.dll` iliyopandikizwa; muunganisho wa named-pipe hutumika kama payload execution signal.<sup>[[4]](#references)</sup>

### Detection pivots

Correlations muhimu ni mahususi zaidi kuliko temporary filename yoyote moja na hufunika namespace transitions zote katika chain:<sup>[[4]](#references)</sup>

- Cloud Files provider iliyosajiliwa hivi karibuni, ikifuatiwa na EICAR detection na `CF_OPERATION_TYPE_RESTART_HYDRATION` kwenye placeholder hiyo hiyo.
- Object Manager paths zilizo na `WD_TARGET_*`, `WD_SHADOW_*`, au `WD_SCAN`, hasa scan path iliyo chini ya `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Uundaji wa CLFS file ukifuatiwa na exclusive whole-file lock na loopback access kwa `\\127.0.0.1\C$\Windows\System32\*.dll` kutoka kwa privileged security process.
- Uundaji wa System32 DLL pamoja na NTFS ADS, ukifuatiwa na `SEC_IMAGE` mapping ya stream.
- WER queue entry iliyoundwa na attacker, ikifuatiwa na manual run isiyo ya kawaida ya `\Microsoft\Windows\Windows Error Reporting\QueueReporting` na image load ya DLL iliyopandikizwa.

## Operational considerations

- **Combine primitives** – Unaweza kutumia jina refu *kwa kila level* katika directory chain ili kupata latency kubwa zaidi hadi umalize ukubwa wa `UNICODE_STRING`.
- **One-shot bugs** – Window iliyopanuliwa (makumi ya microseconds hadi dakika) hufanya “single trigger” bugs ziwe halisi inapounganishwa na CPU affinity pinning au hypervisor-assisted preemption.
- **Side effects** – Slowdown huathiri tu malicious path, kwa hiyo utendaji wa mfumo kwa ujumla hubaki bila kuathiriwa; defenders hawataona kwa urahisi isipokuwa wafuatilie namespace growth.
- **Cleanup** – Hifadhi handles za kila directory/object unayounda ili uweze kuita `NtMakeTemporaryObject`/`NtClose` baadaye. Directory chains zisizo na kikomo zinaweza kubaki baada ya reboots vinginevyo.
- **File-system races** – Ikiwa vulnerable path hatimaye inapitia NTFS, unaweza kuweka Oplock (kwa mfano, `SetOpLock.exe` kutoka toolkit hiyo hiyo) kwenye backing file wakati OM slowdown ikiendelea, na kumfanya consumer asimame kwa milliseconds za ziada bila kubadilisha OM graph.<sup>[[2]](#references)</sup>

## Defensive notes

- Kernel code inayotegemea named objects inapaswa ku-validate tena security-sensitive state *baada* ya open, au ichukue reference kabla ya check (kufunga TOCTOU gap).
- Tekeleza upper bounds kwenye OM path depth/length kabla ya kudereference majina yanayodhibitiwa na user. Kukataa majina marefu kupita kiasi huwalazimisha attackers kurudi kwenye microsecond window.
- Instrument object manager namespace growth (ETW `Microsoft-Windows-Kernel-Object`) ili kugundua chains zenye maelfu ya components zinazotiliwa shaka chini ya `\BaseNamedObjects`.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
