# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Race window को बढ़ाना क्यों महत्वपूर्ण है

कई Windows kernel LPEs classic pattern `check_state(); NtOpenX("name"); privileged_action();` का अनुसरण करते हैं। आधुनिक hardware पर एक cold `NtOpenEvent`/`NtOpenSection` लगभग 2 µs में short name को resolve कर लेता है, जिससे secure action होने से पहले checked state को बदलने के लिए लगभग कोई समय नहीं बचता। Step 2 में Object Manager Namespace (OMNS) lookup को जानबूझकर tens of microseconds तक चलने के लिए मजबूर करके attacker को पर्याप्त समय मिल जाता है और उसे हजारों attempts की आवश्यकता के बिना, अन्यथा flaky races में लगातार जीत मिलती है।<sup>[[1]](#references)</sup>

## Object Manager lookup internals संक्षेप में

* **OMNS structure** – `\BaseNamedObjects\Foo` जैसे names को directory-by-directory resolve किया जाता है। प्रत्येक component के कारण kernel को एक *Object Directory* को find/open करना और Unicode strings की तुलना करनी पड़ती है। रास्ते में symbolic links (जैसे drive letters) को traverse किया जा सकता है।
* **UNICODE_STRING limit** – OM paths एक `UNICODE_STRING` के अंदर carry किए जाते हैं, जिसका `Length` value 16-bit होती है। Absolute limit 65,535 bytes (32,767 UTF-16 codepoints) है। `\BaseNamedObjects\` जैसे prefixes के साथ भी attacker लगभग 32,000 characters को control करता है।
* **Attacker prerequisites** – कोई भी user `\BaseNamedObjects` जैसी writable directories के अंदर objects create कर सकता है। जब vulnerable code अंदर मौजूद name का उपयोग करता है, या ऐसे symbolic link को follow करता है जो वहां पहुंचता है, तो attacker बिना किसी special privileges के lookup performance को control करता है।<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Single maximal component

किसी component को resolve करने की cost उसकी length के साथ लगभग linear होती है, क्योंकि kernel को parent directory में मौजूद प्रत्येक entry के विरुद्ध Unicode comparison करनी पड़ती है। 32 kB-long name वाला event create करने से Windows 11 24H2 (Snapdragon X Elite testbed) पर `NtOpenEvent` latency तुरंत लगभग 2 µs से बढ़कर लगभग 35 µs हो जाती है।
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Practical notes*

- आप किसी भी named kernel object (events, sections, semaphores…) का उपयोग करके length limit तक पहुंच सकते हैं।
- Symbolic links या reparse points एक छोटे “victim” नाम को इस giant component की ओर point कर सकते हैं, जिससे slowdown पारदर्शी रूप से लागू होता है।
- क्योंकि सब कुछ user-writable namespaces में मौजूद रहता है, payload standard user integrity level से काम करता है।<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Deep recursive directories

एक अधिक aggressive variant हजारों directories (`\BaseNamedObjects\A\A\...\X`) की chain allocate करता है। प्रत्येक hop directory resolution logic (ACL checks, hash lookups, reference counting) को trigger करता है, इसलिए per-level latency एक single string compare की तुलना में अधिक होती है। लगभग 16 000 levels के साथ (जो उसी `UNICODE_STRING` size द्वारा limited है), empirical timings long single components द्वारा प्राप्त 35 µs barrier को पार कर जाते हैं।
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

* यदि parent directory duplicates को reject करना शुरू कर दे, तो हर level पर character (`A/B/C/...`) बदलें।
* एक handle array रखें, ताकि exploitation के बाद chain को साफ़-साफ़ delete किया जा सके और namespace pollute न हो।<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (microseconds के बजाय minutes)

Object directories **shadow directories** (fallback lookups) और entries के लिए bucketed hash tables को support करती हैं। दोनों का abuse करें और `UNICODE_STRING` की length बढ़ाए बिना slowdown को कई गुना करने के लिए 64-component symbolic-link reparse limit का उपयोग करें:

1. `\BaseNamedObjects` के अंतर्गत दो directories बनाएँ, जैसे `A` (shadow) और `A\A` (target)। दूसरी directory को पहली directory को shadow directory के रूप में उपयोग करके (`NtCreateDirectoryObjectEx`) बनाएँ, ताकि `A` में missing lookups `A\A` पर fall through हों।
2. प्रत्येक directory को ऐसे हज़ारों **colliding names** से भरें, जो उसी hash bucket में जाएँ (उदाहरण के लिए, trailing digits बदलते रहें, जबकि `RtlHashUnicodeString` value समान रखें)। अब lookups एक ही directory के अंदर O(n) linear scans में degrade हो जाते हैं।
3. लगभग 63 **object manager symbolic links** की chain बनाएँ, जो बार-बार लंबे `A\A\…` suffix में reparse हों और reparse budget का उपयोग करें। प्रत्येक reparse parsing को ऊपर से फिर शुरू करता है, जिससे collision cost कई गुना बढ़ जाती है।
4. अंतिम component (`...\\0`) का lookup अब Windows 11 पर प्रत्येक directory में 16 000 collisions मौजूद होने पर **minutes** लेता है, जिससे one-shot kernel LPEs के लिए race जीतने की practically guaranteed संभावना मिलती है।
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*क्यों महत्वपूर्ण है*: कुछ मिनटों का slowdown one-shot race-based LPEs को deterministic exploits में बदल देता है।<sup>[[1]](#references)</sup>

### 2025 retest notes और ready-made tooling

- James Forshaw ने Windows 11 24H2 (ARM64) पर updated timings के साथ इस technique को फिर से प्रकाशित किया। Baseline opens लगभग ~2 µs पर बने रहते हैं; 32 kB component इसे लगभग ~35 µs तक बढ़ा देता है, और shadow-dir + collision + 63-reparse chains अभी भी ~3 minutes तक पहुँचती हैं, जिससे पुष्टि होती है कि primitives वर्तमान builds में भी काम करते हैं। Source code और perf harness refreshed Project Zero post में हैं।<sup>[[1]](#references)</sup>
- आप public `symboliclink-testing-tools` bundle का उपयोग करके setup को script कर सकते हैं: shadow/target pair बनाने के लिए `CreateObjectDirectory.exe` और 63-hop chain बनाने के लिए loop में `NativeSymlink.exe` चलाएँ। इससे hand-written `NtCreate*` wrappers की आवश्यकता नहीं रहती और ACLs consistent रहते हैं।<sup>[[2]](#references)</sup>

## अपने race window को मापना

अपने exploit के अंदर एक quick harness embed करें, ताकि victim hardware पर window का आकार मापा जा सके। नीचे दिया गया snippet target object को `iterations` बार खोलता है और `QueryPerformanceCounter` का उपयोग करके प्रति-open average cost लौटाता है।<sup>[[1]](#references)</sup>
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
परिणाम सीधे आपकी race orchestration strategy में उपयोग होते हैं (जैसे, कितने worker threads आवश्यक हैं, sleep intervals, और shared state को कितनी जल्दी flip करना है)।

## Exploitation workflow

1. **Vulnerable open का पता लगाएँ** – kernel path को (symbols, ETW, hypervisor tracing या reversing के माध्यम से) तब तक trace करें, जब तक आपको ऐसा `NtOpen*`/`ObOpenObjectByName` call न मिल जाए जो attacker-controlled name या user-writable directory में मौजूद symbolic link को traverse करता हो।
2. **उस name को slow path से बदलें**
- `\BaseNamedObjects` (या किसी अन्य writable OM root) के अंतर्गत long component या directory chain बनाएँ।
- एक symbolic link बनाएँ, ताकि kernel जिस name की अपेक्षा करता है, वह अब slow path पर resolve हो। Original target को छुए बिना vulnerable driver के directory lookup को अपनी structure की ओर point कर सकते हैं।
3. **Race को trigger करें**
- Thread A (victim) vulnerable code execute करता है और slow lookup के भीतर block हो जाता है।
- Thread B (attacker) guarded state को flip करता है (जैसे, file handle swap करना, symbolic link को rewrite करना, या object security को toggle करना), जबकि Thread A व्यस्त रहता है।
- जब Thread A resume होकर privileged action करता है, तो उसे stale state दिखाई देती है और वह attacker-controlled operation करता है।
4. **Clean up करें** – संदिग्ध artifacts छोड़ने या legitimate IPC users को बाधित करने से बचने के लिए directory chain और symbolic links delete करें।<sup>[[1]](#references)</sup>

## Applied chain: mutable Cloud Files placeholders + Object Manager path switching

[RoguePlanet (CVE-2026-50656)](https://github.com/MSNightmare/ShieldBreak) के लिए bypass के रूप में प्रकाशित [ShieldBreak](https://github.com/MSNightmare/ShieldBreak), exploitation pattern को व्यापक रूप में प्रदर्शित करता है: किसी privileged scanner से logical file की एक representation classify करवाएँ, फिर remediation द्वारा उसका उपयोग करने से पहले उसके bytes और namespace resolution दोनों बदल दें। PoC में Cloud Files hydration TOCTOU, Object Manager shadow-directory fallback, CLFS-generated-name capture और local administrative-share link को combine करके Defender cleanup को protected DLL write में बदला जाता है।<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Cloud Files hydration के माध्यम से content substitute करें

किसी attacker-writable directory को Cloud Files sync root के रूप में register करें, `CF_CALLBACK_TYPE_FETCH_DATA` callback connect करें, और ऐसा placeholder बनाएँ जिसका advertised size EICAR ZIP जैसे deterministic detection trigger से match करता हो। पहला fetch trigger लौटाता है और callback state को flip करता है; बाद के fetch payload लौटाते हैं। Scanner द्वारा पहली representation classify किए जाने के बाद, transfer key प्राप्त करें और payload-sized metadata के साथ hydration restart करें, फिर hydration को EOF तक force करें।<sup>[[4]](#references)</sup>
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
सुरक्षा सीमा विफल हो जाती है यदि scan, verdict और remediation केवल किसी pathname या placeholder identity को संदर्भित करते हैं: इनमें से कोई भी यह सुनिश्चित नहीं करता कि बाद में होने वाला hydration उन्हीं bytes को लौटाएगा जिनका निरीक्षण किया गया था।<sup>[[4]](#references)</sup>

### 2. shadow-directory fallback के माध्यम से invariant path को switch करें

`NtCreateDirectoryObjectEx` के साथ एक target Object Manager directory और दूसरी directory बनाएं, तथा target handle को उसकी shadow/fallback directory के रूप में पास करें। दोनों resolution layers में समान नाम वाली `WD_SCAN` entry रखें: visible entry सामान्य working directory की ओर संकेत करे, जबकि fallback entry `\CLFS\??\<working-directory>` की ओर संकेत करे। Defender को केवल नीचे दिया गया invariant path दें; operation सक्रिय होने के दौरान visible link को हटाने पर वही string CLFS-backed entry तक पहुँच जाएगी।<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
यह केवल lookup को धीमा करने के लिए shadow directories का उपयोग करने से अलग है: attacker किसी पहले से स्वीकार किए गए path का **अर्थ** बदले बिना उसकी string में कोई बदलाव करता है।<sup>[[4]](#references)</sup>

### 3. generated name को capture करें और filename-specific link install करें

`ReadDirectoryChangesW` के साथ working directory को monitor करें। पहले `FILE_ACTION_ADDED` पर, fallback lookup को सक्रिय करने के लिए दिखाई देने वाले `WD_SCAN` link को remove करें। दूसरे generated filename को capture करें, उस CLFS-संबंधित file को open करें, और `LockFileEx` के साथ `0..MAXLONGLONG` range को lock करें। privileged operation के stalled रहने के दौरान, visible directory में `WD_SCAN` को एक वास्तविक Object Manager directory से replace करें और observed filename के नाम से एक child symbolic link create करें (PoC इसके अंतिम चार characters को हटा देता है)। इसे local SMB के माध्यम से protected destination की ओर point करें:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
अविशेषाधिकार प्राप्त process स्वयं उस destination में write नहीं कर सकता, लेकिन Defender का SYSTEM context loopback administrative share को traverse कर सकता है। Generated-name observation को filename-specific Object Manager link के साथ मिलाने से remediation artifact का पहले से अनुमान लगाने की आवश्यकता नहीं रहती।<sup>[[4]](#references)</sup>

### 4. Cleanup race को स्थिर करें और privileged loader को trigger करें

Scanning से पहले, PoC placeholder के `:stream` NTFS alternate data stream में एक valid PE (`ntdll.dll`) store करता है। Redirection के protected base file बनाने के बाद, यह `phoneinfo.dll:stream` को execute access के साथ open करता है और `PAGE_EXECUTE_READ | SEC_IMAGE` mapping को जीवित रखता है, जबकि cleanup फिर से शुरू होता है; live file/section objects अंतिम race के दौरान deletion या replacement को सीमित करते हैं। Restarted hydration अब EICAR के बजाय payload DLL लौटाता है, इसलिए protected base file में attacker-controlled code होता है।<sup>[[4]](#references)</sup>

इसके बाद `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` के अंतर्गत एक crafted `Report.wer` रखकर और Task Scheduler COM API के माध्यम से `\Microsoft\Windows\Windows Error Reporting\QueueReporting` invoke करके protected write को SYSTEM execution में बदला जाता है। इस chain में privileged WER processing planted `C:\Windows\System32\phoneinfo.dll` को load करता है; payload execution signal के रूप में named-pipe connection का उपयोग किया जाता है।<sup>[[4]](#references)</sup>

### Detection pivots

Useful correlations किसी एक temporary filename से अधिक specific होते हैं और chain में होने वाले सभी namespace transitions को cover करते हैं:<sup>[[4]](#references)</sup>

- Newly registered Cloud Files provider के बाद उसी placeholder पर EICAR detection और `CF_OPERATION_TYPE_RESTART_HYDRATION`।
- `WD_TARGET_*`, `WD_SHADOW_*`, या `WD_SCAN` वाले Object Manager paths, विशेष रूप से `\\.\globalroot\BaseNamedObjects\Restricted\` के नीचे का scan path।
- CLFS file creation के बाद exclusive whole-file lock और privileged security process से `\\127.0.0.1\C$\Windows\System32\*.dll` तक loopback access।
- NTFS ADS के साथ System32 DLL का creation, जिसके बाद stream की `SEC_IMAGE` mapping।
- Attacker-created WER queue entry के बाद `\Microsoft\Windows\Windows Error Reporting\QueueReporting` का असामान्य manual run और planted DLL का image load।

## Applied chain: privileged remediation के विरुद्ध oplock-gated mount-point switch

एक reusable LPE pattern तब दिखाई देता है जब कोई privileged scanner attacker-controlled file को check करता है और बाद में validated handles के माध्यम से जारी रखने के बजाय **pathname** को फिर से open करके remediation करता है। FalconFlank CrowdStrike Falcon के Office macro-removal workflow को target करने वाला public example है; repository Windows 11 25H2 और Windows Server 2025 पर relevant policy enabled होने के साथ testing का दावा करती है, लेकिन कोई CVE, affected-build range, vendor advisory या patch status प्रकाशित नहीं करती। इसलिए product-specific claim को unverified और build-dependent मानें।<sup>[[5]](#references)[[6]](#references)</sup>

### Race layout

1. ऐसा writable tree बनाएं जिसका अंतिम relative name intended destination पर उपयोगी हो। Example में `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll` का उपयोग किया गया है, लेकिन शुरुआत में `bcrypt.dll` में OLE macro document—PE DLL नहीं—लिखा जाता है। Content-based detection remediation trigger करता है, जबकि बाद के side-load के लिए attacker-controlled basename सुरक्षित रहता है।<sup>[[5]](#references)</sup>
2. Directories को broad sharing और `FILE_OPEN_REPARSE_POINT` के साथ open करें, फिर `FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE`, और `REQUEST_OPLOCK_INPUT_FLAG_REQUEST` के साथ trigger पर asynchronous RH oplock request करें। Overlapped event की प्रतीक्षा करें और उसके completion को path-switch cue के रूप में उपयोग करें। RH oplock-break notification advisory होती है, यह प्रमाण नहीं कि हर conflicting operation block है; इसलिए exploitability अभी भी victim के exact open/remediation sequence पर निर्भर करती है।<sup>[[5]](#references)[[7]](#references)</sup>
3. Break के बाद `FileDispositionInformationEx` (information class 64) से delete और POSIX-semantics flags का उपयोग करके leaf directory हटाएं, उसका handle close करें, और अब-empty parent पर `FSCTL_SET_REPARSE_POINT_EX` के साथ `IO_REPARSE_TAG_MOUNT_POINT` लागू करें। Mount point unchanged suffix को `\\SystemRoot\\System32\\WindowsPowerShell` जैसे protected tree में redirect करता है; यदि directory empty न हो तो reparse point set करना fail होता है, जो preceding deletion step को समझाता है।<sup>[[5]](#references)[[8]](#references)</sup>
4. Privileged workflow को resume करें। यदि वह directory chain और final object के पहले inspect किए गए objects होने का प्रमाण दिए बिना string को फिर से resolve करता है, तो वही logical pathname अब attacker-selected protected directory तक पहुंचता है। Example में success को original process से `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` को read/write के लिए फिर से open करके test किया जाता है; इससे confused-deputy write primitive को बाद के code-execution stage से अलग किया जा सकता है।<sup>[[5]](#references)</sup>
5. Resulting file को real DLL से replace करें और privileged loader को activate करें। PoC `CreateTransaction` + `CreateFileTransacted` का उपयोग करता है, file को truncate करता है, DLL-sized replacement map करता है, PE copy करता है और commit करता है; TxF file handle और बाद के handle-based operations को transaction से bind करता है, लेकिन यह privilege boundary failure का source नहीं बल्कि post-race replacement mechanism है।<sup>[[5]](#references)[[9]](#references)</sup>
6. अंत में, ऐसा existing privileged scheduled task चलाएं जिसका executable planted adjacent filename को probe करता हो। FalconFlank `\\Microsoft\\Windows\\Application Experience\\MareBackup` invoke करता है, DLL के `\\??\\pipe\\FALCONFLANK` से connect होने की प्रतीक्षा करता है और फिर planted file delete करता है। केवल task name के आधार पर किसी विशेष resulting token को assume न करें—tested build पर launched process, module path, integrity level और token verify करें।<sup>[[5]](#references)</sup>

इसलिए core audit question यह नहीं है कि “क्या service original input path को validate करती है?”, बल्कि यह है कि “क्या हर privileged mutation उन्हीं opened file और directory objects से bound रहती है जिन्हें validate किया गया था?” Check और use के बीच handles बनाए रखना, trusted directory handle के relative child objects को open करना, unexpected reparse tags को reject करना और mutation से पहले file identity को revalidate करना pathname-substitution bug की इस class को बंद करता है।<sup>[[1]](#references)[[8]](#references)</sup>

### Detection और PoC triage

High-signal detection namespace transition को privileged consumer के साथ correlate करता है: GUID-named temporary tree में DLL basename के अंतर्गत OLE header, oplock break, leaf directory का POSIX-style removal, protected Windows directory को target करने वाले mount point का creation, और उस destination के नीचे उसी basename का creation या modification। Public example के लिए `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`, `MareBackup` का manual execution और `FALCONFLANK` named pipe जोड़ें; इनमें से कोई भी अकेले पर्याप्त नहीं है।<sup>[[5]](#references)</sup>

PoC को reproduce करते समय published source के तीन reliability defects का ध्यान रखें: यह embedded byte-array pointer को file handle के बजाय `FlushFileBuffers` में pass करता है, `GetFolder`, `GetTask` और `Run` के बाद stale `HRESULT` test करता है, और directory deletion, reparse creation, oplock event तथा pipe connection के लिए unbounded retry/wait loops का उपयोग करता है।<sup>[[5]](#references)</sup>

## Operational considerations

- **Primitives को combine करें** – अधिक latency के लिए directory chain में *प्रति level* एक long name उपयोग कर सकते हैं, जब तक `UNICODE_STRING` size समाप्त न हो जाए।
- **One-shot bugs** – Expanded window (दर्जनों microseconds से minutes तक) CPU affinity pinning या hypervisor-assisted preemption के साथ paired होने पर “single trigger” bugs को realistic बनाती है।
- **Side effects** – Slowdown केवल malicious path को प्रभावित करता है, इसलिए overall system performance अप्रभावित रहती है; defenders को इसका पता बहुत कम चलेगा, जब तक वे namespace growth monitor न करें।
- **Cleanup** – बनाए गए प्रत्येक directory/object के handles रखें, ताकि बाद में `NtMakeTemporaryObject`/`NtClose` call कर सकें। अन्यथा unbounded directory chains reboots के बाद भी बनी रह सकती हैं।
- **File-system races** – यदि vulnerable path अंततः NTFS के माध्यम से resolve होता है, तो OM slowdown के दौरान backing file पर Oplock (जैसे उसी toolkit का `SetOpLock.exe`) stack कर सकते हैं। इससे OM graph बदले बिना consumer को अतिरिक्त milliseconds के लिए freeze किया जा सकता है।<sup>[[2]](#references)</sup>

## Defensive notes

- Named objects पर निर्भर Kernel code को open के *बाद* security-sensitive state को फिर से validate करना चाहिए, या check से पहले reference लेना चाहिए (TOCTOU gap को बंद करने के लिए)।
- User-controlled names को dereference करने से पहले OM path depth/length पर upper bounds लागू करें। अत्यधिक लंबे names को reject करने से attackers microsecond window में वापस आने के लिए मजबूर होते हैं।
- Object manager namespace growth को instrument करें (ETW `Microsoft-Windows-Kernel-Object`), ताकि `\BaseNamedObjects` के अंतर्गत suspicious thousands-of-components chains का पता लगाया जा सके।

## References

- [1] [Project Zero – Windows Exploitation Techniques: Path Lookups के साथ Race Conditions जीतना](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - Transactional NTFS का उपयोग कैसे करें](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
