# Unyonyaji wa Kernel Race Condition kupitia Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Kwa nini kuongeza race window ni muhimu

Windows kernel LPE nyingi hufuata muundo wa kawaida `check_state(); NtOpenX("name"); privileged_action();`. Kwenye hardware ya kisasa, `NtOpenEvent`/`NtOpenSection` yenye jina fupi na cold huweza kutatuliwa kwa takriban ~2 µs, hivyo kubaki na muda mdogo sana wa kubadilisha state iliyokaguliwa kabla ya secure action kutekelezwa. Kwa kulazimisha lookup ya Object Manager Namespace (OMNS) katika hatua ya 2 ichukue makumi ya microseconds, attacker hupata muda wa kutosha kushinda race kwa uthabiti, hata zile race ambazo kwa kawaida hazitabiriki, bila kuhitaji majaribio maelfu.<sup>[[1]](#references)</sup>

## Muhtasari wa lookup internals za Object Manager

* **Muundo wa OMNS** – Majina kama `\BaseNamedObjects\Foo` hutatuliwa directory-by-directory. Kila component husababisha kernel kutafuta/kufungua *Object Directory* na kulinganisha Unicode strings. Symbolic links (kwa mfano, drive letters) zinaweza kufuatwa njiani.
* **Kikomo cha UNICODE_STRING** – OM paths hubebwa ndani ya `UNICODE_STRING` ambayo `Length` yake ni value ya 16-bit. Kikomo cha juu kabisa ni bytes 65 535 (UTF-16 codepoints 32 767). Kwa prefixes kama `\BaseNamedObjects\`, attacker bado anadhibiti takriban characters 32 000.
* **Masharti ya attacker** – Mtumiaji yeyote anaweza kuunda objects ndani ya directories zinazoweza kuandikwa kama `\BaseNamedObjects`. Wakati vulnerable code inapotumia jina lililo ndani yake, au kufuata symbolic link inayoishia humo, attacker hudhibiti lookup performance bila special privileges.<sup>[[1]](#references)</sup>

## Mbinu ya kupunguza kasi #1 – Component moja yenye urefu wa juu zaidi

Gharama ya kutatua component huwa karibu linear kulingana na urefu wake kwa sababu kernel lazima ifanye Unicode comparison dhidi ya kila entry katika parent directory. Kuunda event yenye jina lenye urefu wa 32 kB huongeza mara moja latency ya `NtOpenEvent` kutoka ~2 µs hadi ~35 µs kwenye Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Maelezo ya kiutendaji*

- Unaweza kufikia kikomo cha urefu kwa kutumia kernel object yoyote yenye jina (events, sections, semaphores…).
- Symbolic links au reparse points zinaweza kuelekeza jina fupi la “victim” kwenye component hii kubwa, hivyo slowdown itekelezwe transparently.
- Kwa kuwa kila kitu kiko kwenye namespaces zinazoandikika na user, payload hufanya kazi kutoka kwenye kiwango cha kawaida cha user integrity.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Directories za deep recursive

Variant yenye ukali zaidi hu-allocate chain ya maelfu ya directories (`\BaseNamedObjects\A\A\...\X`). Kila hop hu-trigger directory resolution logic (ACL checks, hash lookups, reference counting), kwa hiyo latency ya kila level huwa kubwa kuliko ile ya string compare moja. Kwa takriban levels 16,000 (zinazowekewa kikomo na ukubwa huohuo wa `UNICODE_STRING`), timings za majaribio huzidi kizingiti cha 35 µs kilichofikiwa na components ndefu moja moja.
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
* Hifadhi array ya handles ili uweze kufuta chain kwa usafi baada ya exploitation, kuepuka kuchafua namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (dakika badala ya microseconds)

Object directories zinaunga mkono **shadow directories** (fallback lookups) na hash tables zenye buckets kwa entries. Tumia vibaya zote mbili pamoja na kikomo cha 64-component symbolic-link reparse ili kuongeza slowdown mara nyingi bila kuzidi urefu wa `UNICODE_STRING`:

1. Create directories mbili chini ya `\BaseNamedObjects`, kwa mfano `A` (shadow) na `A\A` (target). Create ya pili ukitumia ya kwanza kama shadow directory (`NtCreateDirectoryObjectEx`), ili missing lookups katika `A` zipitie hadi `A\A`.
2. Jaza kila directory kwa maelfu ya **colliding names** zinazoangukia kwenye hash bucket moja (kwa mfano, badilisha trailing digits huku ukiweka thamani ileile ya `RtlHashUnicodeString`). Lookups sasa hupungua hadi O(n) linear scans ndani ya directory moja.
3. Tengeneza chain ya takriban **63 object manager symbolic links** ambazo hurudia kureparse ndani ya suffix ndefu ya `A\A\…`, zikitumia reparse budget. Kila reparse huanza tena parsing kutoka juu, na kuongeza collision cost mara nyingi.
4. Lookup ya final component (`...\\0`) sasa huchukua **dakika** kwenye Windows 11 wakati collisions 16 000 zipo kwa kila directory, hivyo kutoa race win inayokaribia kuhakikishwa kwa one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Kwa nini ni muhimu*: Kupungua kwa kasi kwa muda wa dakika hubadilisha LPEs za one-shot race-based kuwa exploits za kuaminika.<sup>[[1]](#references)</sup>

### Maelezo ya retest ya 2025 na tooling iliyotengenezwa tayari

- James Forshaw alichapisha tena technique hii ikiwa na vipimo vya muda vilivyosasishwa kwenye Windows 11 24H2 (ARM64). Opens za msingi bado ni takriban ~2 µs; component ya 32 kB huongeza thamani hii hadi ~35 µs, na shadow-dir + collision + 63-reparse chains bado hufikia ~dakika 3, kuthibitisha kwamba primitives bado zinafanya kazi kwenye builds za sasa. Source code na perf harness zinapatikana katika post iliyosasishwa ya Project Zero.<sup>[[1]](#references)</sup>
- Unaweza kuscript setup kwa kutumia bundle ya umma ya `symboliclink-testing-tools`: `CreateObjectDirectory.exe` ili kuanzisha shadow/target pair na `NativeSymlink.exe` ndani ya loop ili kutoa 63-hop chain. Hii huepuka kuandika mwenyewe `NtCreate*` wrappers na hudumisha ACLs zikiwa thabiti.<sup>[[2]](#references)</sup>

## Kupima race window yako

Embed harness fupi ndani ya exploit yako ili kupima ukubwa wa window kwenye hardware ya victim. Snippet iliyo hapa chini hufungua target object mara `iterations` na kurudisha wastani wa gharama ya kila open kwa kutumia `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Matokeo huingia moja kwa moja kwenye mkakati wako wa race orchestration (kwa mfano, idadi ya worker threads zinazohitajika, vipindi vya kusubiri, na muda wa kugeuza shared state).

## Mtiririko wa exploitation

1. **Tambua open iliyo katika mazingira hatarishi** – Fuatilia kernel path (kupitia symbols, ETW, hypervisor tracing, au reversing) hadi upate mwito wa `NtOpen*`/`ObOpenObjectByName` unaopitia jina linalodhibitiwa na mshambuliaji au symbolic link katika directory inayoweza kuandikwa na mtumiaji.
2. **Badilisha jina hilo litumie slow path**
- Unda long component au directory chain chini ya `\BaseNamedObjects` (au OM root nyingine inayoweza kuandikwa).
- Unda symbolic link ili jina linalotarajiwa na kernel sasa lielekeze kwenye slow path. Unaweza kuelekeza directory lookup ya vulnerable driver kwenye muundo wako bila kugusa target ya awali.
3. **Anzisha race**
- Thread A (mwathiriwa) hutekeleza code iliyo katika mazingira hatarishi na kuzuiwa ndani ya slow lookup.
- Thread B (mshambuliaji) hubadilisha guarded state (kwa mfano, hubadilisha file handle, huandika upya symbolic link, au hubadilisha object security) wakati Thread A iko bize.
- Thread A inapoendelea na kutekeleza privileged action, huona state ya zamani na kutekeleza operation inayodhibitiwa na mshambuliaji.
4. **Fanya cleanup** – Futa directory chain na symbolic links ili kuepuka kuacha suspicious artifacts au kuvuruga watumiaji halali wa IPC.<sup>[[1]](#references)</sup>

## Applied chain: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), iliyochapishwa kama bypass ya RoguePlanet (CVE-2026-50656), inaonyesha exploitation pattern pana zaidi: fanya privileged scanner iainishe representation moja ya logical file, kisha ubadilishe bytes zake na namespace resolution kabla remediation haijaitumia. PoC inaunganisha Cloud Files hydration TOCTOU, Object Manager shadow-directory fallback, CLFS-generated-name capture, na local administrative-share link ili kubadilisha Defender cleanup kuwa protected DLL write.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Badilisha content kupitia Cloud Files hydration

Sajili directory inayoweza kuandikwa na mshambuliaji kama Cloud Files sync root, unganisha callback ya `CF_CALLBACK_TYPE_FETCH_DATA`, na uunde placeholder ambayo advertised size yake inalingana na deterministic detection trigger kama EICAR ZIP. Fetch ya kwanza hurejesha trigger na kubadilisha callback state; fetch zinazofuata hurejesha payload. Baada ya scanner kuainisha representation ya kwanza, pata transfer key na uanze upya hydration kwa metadata yenye ukubwa wa payload, kisha force hydration hadi EOF.<sup>[[4]](#references)</sup>
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
Mpaka wa usalama hushindwa ikiwa scan, verdict, na remediation zinarejelea tu pathname au utambulisho wa placeholder: hakuna kinachohakikisha kwamba hydration ya baadaye itarejesha bytes zilizokaguliwa.<sup>[[4]](#references)</sup>

### 2. Badilisha invariant path kupitia shadow-directory fallback

Unda directory ya Object Manager inayolengwa na directory ya pili kwa `NtCreateDirectoryObjectEx`, ukipitisha handle ya lengo kama directory yake ya shadow/fallback. Weka entry ya `WD_SCAN` yenye jina lilelile katika tabaka zote mbili za resolution: entry inayoonekana ielekeze kwenye working directory ya kawaida, huku entry ya fallback ielekeze kwenye `\CLFS\??\<working-directory>`. Mpe Defender invariant path iliyo hapa chini pekee; kufuta link inayoonekana wakati operesheni inaendelea hufanya string ileile ipitie kwenye entry inayotegemea CLFS.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Hii ni tofauti na kutumia shadow directories pekee ili kupunguza kasi ya utafutaji: mshambulizi hubadilisha **maana** ya path iliyokubaliwa hapo awali bila kubadilisha string yake.<sup>[[4]](#references)</sup>

### 3. Capture generated name and install a filename-specific link

Fuatilia working directory kwa kutumia `ReadDirectoryChangesW`. Kwenye `FILE_ACTION_ADDED` ya kwanza, ondoa link inayoonekana ya `WD_SCAN` ili kuamilisha fallback lookup. Capture filename ya pili iliyozalishwa, fungua hiyo faili inayohusiana na CLFS, na lock range `0..MAXLONGLONG` kwa `LockFileEx`. Wakati privileged operation imesitishwa, badilisha `WD_SCAN` katika directory inayoonekana iwe directory halisi ya Object Manager, kisha uunde child symbolic link iliyopewa jina kutokana na filename iliyozingatiwa (PoC huondoa characters zake nne za mwisho). Ielekeze kwenye protected destination kupitia local SMB:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Mchakato usio na privileges hauwezi kuandika destination hiyo wenyewe, lakini context ya SYSTEM ya Defender inaweza kupitia administrative share ya loopback. Kuchanganya ufuatiliaji wa majina yanayozalishwa na Object Manager link maalum kwa filename huondoa hitaji la kutabiri artifact ya remediation mapema.<sup>[[4]](#references)</sup>

### 4. Imarisha cleanup race na uanzishe privileged loader

Kabla ya scanning, PoC huhifadhi PE halali (`ntdll.dll`) katika NTFS alternate data stream ya `:stream` ya placeholder. Baada ya redirection kuunda base file iliyolindwa, hufungua `phoneinfo.dll:stream` kwa execute access na kuweka mapping ya `PAGE_EXECUTE_READ | SEC_IMAGE` hai wakati cleanup ikiendelea; file/section objects zilizo hai huzuia deletion au replacement wakati wa race ya mwisho. Hydration iliyoanzishwa upya sasa hurudisha payload DLL badala ya EICAR, hivyo protected base file huwa na code inayodhibitiwa na attacker.<sup>[[4]](#references)</sup>

Protected write hubadilishwa kuwa SYSTEM execution kwa kuweka `Report.wer` iliyotengenezwa chini ya `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` na kuita `\Microsoft\Windows\Windows Error Reporting\QueueReporting` kupitia Task Scheduler COM API. Katika chain hii, privileged WER processing hupakia `C:\Windows\System32\phoneinfo.dll` iliyopandikizwa; muunganisho wa named pipe hutumika kama ishara ya payload execution.<sup>[[4]](#references)</sup>

### Detection pivots

Correlations muhimu ni mahususi zaidi kuliko filename yoyote ya muda na hufunika mabadiliko yote ya namespace katika chain:<sup>[[4]](#references)</sup>

- Cloud Files provider iliyosajiliwa hivi karibuni ikifuatiwa na EICAR detection na `CF_OPERATION_TYPE_RESTART_HYDRATION` kwenye placeholder hiyo hiyo.
- Object Manager paths zenye `WD_TARGET_*`, `WD_SHADOW_*`, au `WD_SCAN`, hasa scan path iliyo chini ya `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Uundaji wa CLFS file ukifuatiwa na exclusive whole-file lock na loopback access ya `\\127.0.0.1\C$\Windows\System32\*.dll` kutoka kwa privileged security process.
- Uundaji wa System32 DLL pamoja na NTFS ADS, ukifuatiwa na `SEC_IMAGE` mapping ya stream.
- WER queue entry iliyoundwa na attacker ikifuatiwa na manual run isiyo ya kawaida ya `\Microsoft\Windows\Windows Error Reporting\QueueReporting` na image load ya DLL iliyopandikizwa.

## Applied chain: oplock-gated mount-point switch dhidi ya privileged remediation

Pattern ya LPE inayoweza kutumika tena hujitokeza wakati privileged scanner inapokagua file inayodhibitiwa na attacker na baadaye kuifanyia remediation kwa kufungua tena **pathname**, badala ya kuendelea kupitia handles zilizothibitishwa. FalconFlank ni mfano wa umma unaolenga workflow ya CrowdStrike Falcon ya kuondoa Office macro; repository inadai testing kwenye Windows 11 25H2 na Windows Server 2025 ikiwa policy husika imewezeshwa, lakini haichapishi CVE, affected-build range, vendor advisory, au patch status, hivyo dai mahususi la product lichukuliwe kuwa halijathibitishwa na linalotegemea build.<sup>[[5]](#references)[[6]](#references)</sup>

### Race layout

1. Tengeneza writable tree yenye relative name ya mwisho inayofaa kwenye destination iliyokusudiwa. Mfano hutumia `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll`, lakini mwanzoni huandika OLE macro document—si PE DLL—kwenye `bcrypt.dll`. Content-based detection huanzisha remediation huku basename inayodhibitiwa na attacker ikihifadhiwa kwa side-load ya baadaye.<sup>[[5]](#references)</sup>
2. Fungua directories kwa broad sharing na `FILE_OPEN_REPARSE_POINT`, kisha omba asynchronous RH oplock kwenye trigger kwa `FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE`, na `REQUEST_OPLOCK_INPUT_FLAG_REQUEST`. Subiri overlapped event na utumie completion yake kama path-switch cue. RH oplock-break notification ni advisory badala ya uthibitisho kwamba kila conflicting operation imezuiwa, hivyo exploitability bado hutegemea open/remediation sequence halisi ya victim.<sup>[[5]](#references)[[7]](#references)</sup>
3. Baada ya break, ondoa leaf directory kwa `FileDispositionInformationEx` (information class 64) ukitumia delete pamoja na POSIX-semantics flags, funga handle yake, na weka `IO_REPARSE_TAG_MOUNT_POINT` kwenye parent ambayo sasa haina kitu kwa `FSCTL_SET_REPARSE_POINT_EX`. Mount point huelekeza suffix isiyobadilika kwenye protected tree kama `\\SystemRoot\\System32\\WindowsPowerShell`; kuweka reparse point hushindikana ikiwa directory si tupu, jambo linaloeleza hatua ya deletion iliyotangulia.<sup>[[5]](#references)[[8]](#references)</sup>
4. Endeleza privileged workflow. Ikiwa itasolve string hiyo tena bila kuthibitisha kwamba directory chain na final object ni zile zilizokaguliwa awali, pathname ileile ya kimantiki sasa hufikia protected directory iliyochaguliwa na attacker. Katika mfano, mafanikio hupimwa kwa kufungua tena `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` kwa read/write kutoka kwa process ya awali; hii hutenganisha confused-deputy write primitive na hatua ya baadaye ya code execution.<sup>[[5]](#references)</sup>
5. Replace file iliyopatikana kwa DLL halisi na uwashe privileged loader. PoC hutumia `CreateTransaction` + `CreateFileTransacted`, hutruncate file, hu-map replacement yenye ukubwa wa DLL, hunakili PE, na kufanya commit; TxF hufunga file handle na operations zinazofuata za handle kwenye transaction, lakini ni post-race replacement mechanism, si chanzo cha kushindwa kwa privilege boundary.<sup>[[5]](#references)[[9]](#references)</sup>
6. Mwishowe, endesha existing privileged scheduled task ambayo executable yake huchunguza adjacent filename iliyopandikizwa. FalconFlank huita `\\Microsoft\\Windows\\Application Experience\\MareBackup`, husubiri DLL iunganishwe na `\\??\\pipe\\FALCONFLANK`, kisha hufuta file iliyopandikizwa. Usidhani token inayopatikana kutokana na task name pekee—thibitisha launched process, module path, integrity level, na token kwenye build iliyojaribiwa.<sup>[[5]](#references)</sup>

Swali kuu la audit kwa hiyo si “je, service inathibitisha original input path?” bali “je, kila privileged mutation inabaki imefungwa kwenye file na directory objects zilezile zilizothibitishwa?” Kushikilia handles wakati wa check na use, kufungua child objects relative to trusted directory handle, kukataa unexpected reparse tags, na kuthibitisha upya file identity kabla ya mutation hufunga aina hii ya pathname-substitution bug.<sup>[[1]](#references)[[8]](#references)</sup>

### Detection na PoC triage

High-signal detection huunganisha namespace transition na privileged consumer: OLE header chini ya DLL basename katika temporary tree yenye jina la GUID, oplock break, POSIX-style removal ya leaf directory, uundaji wa mount point inayolenga protected Windows directory, na uundaji au modification ya basename hiyo hiyo chini ya destination hiyo. Kwa mfano wa umma, ongeza `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`, manual execution ya `MareBackup`, na named pipe ya `FALCONFLANK` kama pivots nyembamba zaidi; hakuna kimoja kinachotosha peke yake.<sup>[[5]](#references)</sup>

Unapozalisha PoC tena, zingatia reliability defects tatu katika source iliyochapishwa: inaita `FlushFileBuffers` kwa embedded byte-array pointer badala ya file handle, inajaribu `HRESULT` iliyopitwa na wakati baada ya `GetFolder`, `GetTask`, na `Run`, na hutumia retry/wait loops zisizo na kikomo kwa directory deletion, reparse creation, oplock event, na pipe connection.<sup>[[5]](#references)</sup>

## Operational considerations

- **Combine primitives** – Unaweza kutumia long name *kwa kila level* katika directory chain ili kupata latency kubwa zaidi hadi umalize `UNICODE_STRING` size.
- **One-shot bugs** – Expanded window (makumi ya microseconds hadi dakika) hufanya “single trigger” bugs ziwe halisi zinapounganishwa na CPU affinity pinning au hypervisor-assisted preemption.
- **Side effects** – Slowdown huathiri path hasidi pekee, hivyo performance ya mfumo mzima hubaki bila kuathirika; defenders mara chache wataona jambo hilo isipokuwa wafuatilie namespace growth.
- **Cleanup** – Hifadhi handles za kila directory/object unayounda ili uweze kuita `NtMakeTemporaryObject`/`NtClose` baadaye. Directory chains zisizo na kikomo zinaweza kubaki baada ya reboots vinginevyo.
- **File-system races** – Ikiwa vulnerable path hatimaye inasolve kupitia NTFS, unaweza kuweka Oplock (kwa mfano, `SetOpLock.exe` kutoka toolkit hiyo hiyo) kwenye backing file wakati OM slowdown ikiendelea, na kumgandisha consumer kwa milliseconds zaidi bila kubadilisha OM graph.<sup>[[2]](#references)</sup>

## Defensive notes

- Kernel code inayotegemea named objects inapaswa kuthibitisha tena security-sensitive state *baada* ya open, au ichukue reference kabla ya check (kufunga TOCTOU gap).
- Weka upper bounds kwenye OM path depth/length kabla ya kudereference majina yanayodhibitiwa na user. Kukataa majina marefu kupita kiasi huwalazimisha attackers kurudi kwenye microsecond window.
- Instrument object manager namespace growth (ETW `Microsoft-Windows-Kernel-Object`) ili kugundua chains zenye maelfu ya components chini ya `\BaseNamedObjects`.

## References

- [1] [Project Zero – Mbinu za Windows Exploitation: Kushinda Race Conditions kwa Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - Jinsi ya Kutumia Transactional NTFS](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
