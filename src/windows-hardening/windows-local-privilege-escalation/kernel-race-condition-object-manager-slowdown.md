# Object Manager Slow Paths के जरिए Kernel Race Condition Exploitation

{{#include ../../banners/hacktricks-training.md}}

## Race window को बढ़ाना क्यों महत्वपूर्ण है

कई Windows kernel LPEs classic pattern `check_state(); NtOpenX("name"); privileged_action();` का पालन करते हैं। आधुनिक hardware पर एक cold `NtOpenEvent`/`NtOpenSection` लगभग 2 µs में short name को resolve कर देता है, जिससे secure action होने से पहले checked state को बदलने के लिए लगभग कोई समय नहीं बचता। Step 2 में Object Manager Namespace (OMNS) lookup को जानबूझकर tens of microseconds तक चलने के लिए मजबूर करके, attacker को हजारों attempts की आवश्यकता के बिना अन्यथा flaky races को लगातार जीतने के लिए पर्याप्त समय मिल जाता है।<sup>[[1]](#references)</sup>

## Object Manager lookup internals संक्षेप में

* **OMNS structure** – `\BaseNamedObjects\Foo` जैसे names को directory-by-directory resolve किया जाता है। प्रत्येक component के कारण kernel को एक *Object Directory* find/open करनी पड़ती है और Unicode strings की तुलना करनी पड़ती है। रास्ते में symbolic links (जैसे drive letters) traverse किए जा सकते हैं।
* **UNICODE_STRING limit** – OM paths को एक `UNICODE_STRING` के अंदर रखा जाता है, जिसका `Length` एक 16-bit value होता है। Absolute limit 65 535 bytes (32 767 UTF-16 codepoints) है। `\BaseNamedObjects\` जैसे prefixes के साथ भी attacker लगभग 32 000 characters को control करता है।
* **Attacker prerequisites** – कोई भी user `\BaseNamedObjects` जैसी writable directories के अंदर objects create कर सकता है। जब vulnerable code अंदर मौजूद name का उपयोग करता है, या ऐसी symbolic link को follow करता है जो वहां पहुंचती है, तो attacker बिना special privileges के lookup performance को control करता है।<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Single maximal component

किसी component को resolve करने की cost उसकी length के साथ roughly linear होती है, क्योंकि kernel को parent directory में मौजूद प्रत्येक entry के विरुद्ध Unicode comparison करनी पड़ती है। 32 kB-long name वाला event create करने से Windows 11 24H2 (Snapdragon X Elite testbed) पर `NtOpenEvent` latency तुरंत ~2 µs से बढ़कर ~35 µs हो जाती है.
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*व्यावहारिक टिप्पणियाँ*

- आप किसी भी named kernel object (events, sections, semaphores…) का उपयोग करके length limit तक पहुँच सकते हैं।
- Symbolic links या reparse points एक छोटे “victim” नाम को इस विशाल component की ओर point कर सकते हैं, जिससे slowdown transparently लागू होता है।
- क्योंकि सब कुछ user-writable namespaces में रहता है, payload standard user integrity level से काम करता है।<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – गहरी recursive directories

एक अधिक aggressive variant हजारों directories की एक chain (`\BaseNamedObjects\A\A\...\X`) allocate करता है। प्रत्येक hop directory resolution logic (ACL checks, hash lookups, reference counting) को trigger करता है, इसलिए per-level latency single string compare की तुलना में अधिक होती है। लगभग 16 000 levels (उसी `UNICODE_STRING` size द्वारा सीमित) के साथ, empirical timings long single components द्वारा प्राप्त 35 µs barrier को पार कर जाती हैं।
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

* यदि parent directory duplicates अस्वीकार करना शुरू कर दे, तो प्रति level character (`A/B/C/...`) बदलें।
* एक handle array रखें, ताकि exploitation के बाद chain को साफ़-साफ़ delete किया जा सके और namespace pollute न हो।<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (microseconds के बजाय minutes)

Object directories **shadow directories** (fallback lookups) और entries के लिए bucketed hash tables को support करती हैं। दोनों का abuse करें और `UNICODE_STRING` length बढ़ाए बिना slowdown को कई गुना करने के लिए 64-component symbolic-link reparse limit का उपयोग करें:

1. `\BaseNamedObjects` के अंतर्गत दो directories बनाएँ, जैसे `A` (shadow) और `A\A` (target)। दूसरी directory को पहली directory के shadow directory के रूप में उपयोग करके (`NtCreateDirectoryObjectEx`) बनाएँ, ताकि `A` में missing lookups `A\A` पर fall through हों।
2. प्रत्येक directory को ऐसे हजारों **colliding names** से भरें जो उसी hash bucket में जाएँ (जैसे trailing digits बदलते रहें, लेकिन वही `RtlHashUnicodeString` value बनाए रखें)। अब lookups एक ही directory के भीतर O(n) linear scans तक degrade हो जाते हैं।
3. लगभग 63 **object manager symbolic links** की chain बनाएँ, जो बार-बार लंबे `A\A\…` suffix में reparse हों और reparse budget को consume करें। प्रत्येक reparse parsing को ऊपर से फिर शुरू करता है, जिससे collision cost कई गुना बढ़ जाती है।
4. अब अंतिम component (`...\\0`) का lookup Windows 11 पर प्रति directory 16 000 collisions मौजूद होने पर **minutes** लेता है, जिससे one-shot kernel LPEs के लिए race जीतने की practically guaranteed संभावना मिलती है।
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

- James Forshaw ने Windows 11 24H2 (ARM64) पर updated timings के साथ इस technique को फिर से प्रकाशित किया। Baseline opens अब भी ~2 µs रहते हैं; 32 kB component इसे ~35 µs तक बढ़ाता है, और shadow-dir + collision + 63-reparse chains अब भी ~3 minutes तक पहुँचती हैं, जिससे पुष्टि होती है कि primitives current builds में भी मौजूद हैं। Source code और perf harness refreshed Project Zero post में हैं।<sup>[[1]](#references)</sup>
- आप public `symboliclink-testing-tools` bundle का उपयोग करके setup को script कर सकते हैं: shadow/target pair बनाने के लिए `CreateObjectDirectory.exe` और 63-hop chain बनाने के लिए loop में `NativeSymlink.exe` चलाएँ। इससे hand-written `NtCreate*` wrappers की आवश्यकता नहीं रहती और ACLs consistent रहते हैं।<sup>[[2]](#references)</sup>

## अपनी race window को मापना

अपने exploit में एक quick harness शामिल करें, ताकि victim hardware पर window कितनी बड़ी होती है, यह मापा जा सके। नीचे दिया गया snippet target object को `iterations` बार खोलता है और `QueryPerformanceCounter` का उपयोग करके average per-open cost लौटाता है।<sup>[[1]](#references)</sup>
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
परिणाम सीधे आपकी race orchestration strategy में feed होते हैं (जैसे, आवश्यक worker threads की संख्या, sleep intervals, और shared state को कितनी जल्दी flip करना है)।

## Exploitation workflow

1. **Vulnerable open का पता लगाएँ** – symbols, ETW, hypervisor tracing या reversing के माध्यम से kernel path को trace करें, जब तक आपको ऐसा `NtOpen*`/`ObOpenObjectByName` call न मिल जाए जो user-writable directory में attacker-controlled name या symbolic link को traverse करता हो।
2. **उस name को slow path से replace करें**
- `\BaseNamedObjects` (या किसी अन्य writable OM root) के अंतर्गत लंबा component या directory chain बनाएँ।
- एक symbolic link बनाएँ ताकि kernel द्वारा अपेक्षित name अब slow path पर resolve हो। आप vulnerable driver के directory lookup को अपनी structure की ओर point कर सकते हैं, बिना original target को छुए।
3. **Race trigger करें**
- Thread A (victim) vulnerable code को execute करता है और slow lookup के भीतर block हो जाता है।
- Thread B (attacker) Thread A के व्यस्त रहने के दौरान guarded state को flip करता है (जैसे, file handle swap करना, symbolic link को rewrite करना, या object security को toggle करना)।
- जब Thread A resume होकर privileged action करता है, तो उसे stale state दिखाई देती है और वह attacker-controlled operation execute करता है।
4. **Cleanup करें** – संदिग्ध artifacts छोड़ने या legitimate IPC users को बाधित करने से बचने के लिए directory chain और symbolic links को delete करें।<sup>[[1]](#references)</sup>

## Applied chain: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), जिसे RoguePlanet (CVE-2026-50656) के लिए bypass के रूप में प्रकाशित किया गया था, एक व्यापक exploitation pattern प्रदर्शित करता है: एक privileged scanner से logical file के एक representation को classify करवाएँ, फिर remediation द्वारा उसका उपयोग किए जाने से पहले उसके bytes और namespace resolution दोनों को बदल दें। PoC में Cloud Files hydration TOCTOU, Object Manager shadow-directory fallback, CLFS-generated-name capture और local administrative-share link को combine करके Defender cleanup को protected DLL write में बदला जाता है।<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Cloud Files hydration के माध्यम से content substitute करें

एक attacker-writable directory को Cloud Files sync root के रूप में register करें, `CF_CALLBACK_TYPE_FETCH_DATA` callback connect करें, और ऐसा placeholder बनाएँ जिसका advertised size EICAR ZIP जैसे deterministic detection trigger से match करता हो। पहला fetch trigger return करता है और callback state को flip करता है; बाद के fetch payload return करते हैं। Scanner द्वारा पहले representation को classify करने के बाद, transfer key प्राप्त करें और payload-sized metadata के साथ hydration restart करें, फिर hydration को EOF तक force करें।<sup>[[4]](#references)</sup>
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
सुरक्षा सीमा विफल हो जाती है यदि scan, verdict और remediation केवल pathname या placeholder identity को संदर्भित करते हैं: इनमें से कोई भी यह सुनिश्चित नहीं करता कि बाद में होने वाला hydration वही bytes लौटाएगा जिनका inspection किया गया था।<sup>[[4]](#references)</sup>

### 2. shadow-directory fallback के माध्यम से invariant path को switch करना

`NtCreateDirectoryObjectEx` के साथ एक target Object Manager directory और दूसरी directory बनाएँ, तथा target handle को उसकी shadow/fallback directory के रूप में पास करें। दोनों resolution layers में समान नाम वाली `WD_SCAN` entry रखें: visible entry सामान्य working directory की ओर संकेत करे, जबकि fallback entry `\CLFS\??\<working-directory>` की ओर संकेत करे। Defender को नीचे दिया गया केवल invariant path दें; operation सक्रिय रहने के दौरान visible link को delete करने पर वही string CLFS-backed entry तक fall through हो जाती है।<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
यह केवल lookup को धीमा करने के लिए shadow directories का उपयोग करने से अलग है: attacker पहले से स्वीकार किए गए path का **meaning** बदले बिना उसकी string में संशोधन किए बदल देता है।<sup>[[4]](#references)</sup>

### 3. generated name को capture करें और filename-specific link install करें

`ReadDirectoryChangesW` के साथ working directory को monitor करें। पहले `FILE_ACTION_ADDED` पर fallback lookup को activate करने के लिए दिखाई देने वाले `WD_SCAN` link को remove करें। दूसरे generated filename को capture करें, उस CLFS-related file को open करें और `LockFileEx` के साथ `0..MAXLONGLONG` range को lock करें। privileged operation के stalled रहने के दौरान, visible directory में `WD_SCAN` को एक real Object Manager directory से replace करें और observed filename के नाम से एक child symbolic link create करें (PoC इसके अंतिम चार characters को हटा देता है)। इसे local SMB के माध्यम से protected destination की ओर point करें:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
अविशेषाधिकार प्राप्त process उस destination में स्वयं write नहीं कर सकता, लेकिन Defender का SYSTEM context loopback administrative share को traverse कर सकता है। Generated-name observation को filename-specific Object Manager link के साथ मिलाने से remediation artifact का पहले से अनुमान लगाने की आवश्यकता नहीं रहती।<sup>[[4]](#references)</sup>

### 4. Cleanup race को स्थिर करें और privileged loader को trigger करें

Scanning से पहले, PoC placeholder के `:stream` NTFS alternate data stream में एक valid PE (`ntdll.dll`) store करता है। Redirection द्वारा protected base file बनाने के बाद, यह `phoneinfo.dll:stream` को execute access के साथ open करता है और एक `PAGE_EXECUTE_READ | SEC_IMAGE` mapping को जीवित रखता है, जबकि cleanup फिर से शुरू होता है; live file/section objects अंतिम race के दौरान deletion या replacement को सीमित करते हैं। Restarted hydration अब EICAR के बजाय payload DLL लौटाता है, इसलिए protected base file में attacker-controlled code मौजूद होता है।<sup>[[4]](#references)</sup>

इसके बाद `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` के अंतर्गत एक crafted `Report.wer` रखकर और Task Scheduler COM API के माध्यम से `\Microsoft\Windows\Windows Error Reporting\QueueReporting` को invoke करके protected write को SYSTEM execution में बदला जाता है। इस chain में, privileged WER processing planted `C:\Windows\System32\phoneinfo.dll` को load करता है; एक named-pipe connection का उपयोग payload execution signal के रूप में किया जाता है।<sup>[[4]](#references)</sup>

### Detection pivots

Useful correlations किसी एक temporary filename से अधिक specific होते हैं और chain में होने वाले सभी namespace transitions को cover करते हैं:<sup>[[4]](#references)</sup>

- Newly registered Cloud Files provider, जिसके बाद उसी placeholder पर EICAR detection और `CF_OPERATION_TYPE_RESTART_HYDRATION` हो।
- `WD_TARGET_*`, `WD_SHADOW_*`, या `WD_SCAN` वाले Object Manager paths, विशेष रूप से `\\.\globalroot\BaseNamedObjects\Restricted\` के नीचे का scan path।
- CLFS file creation, जिसके बाद exclusive whole-file lock और किसी privileged security process से `\\127.0.0.1\C$\Windows\System32\*.dll` तक loopback access हो।
- NTFS ADS के साथ System32 DLL का creation, जिसके बाद stream की `SEC_IMAGE` mapping हो।
- Attacker-created WER queue entry, जिसके बाद `\Microsoft\Windows\Windows Error Reporting\QueueReporting` का असामान्य manual run और planted DLL का image load हो।

## Operational considerations

- **Combine primitives** – आप directory chain में *प्रति level* एक long name का उपयोग करके `UNICODE_STRING` size समाप्त होने तक और अधिक latency प्राप्त कर सकते हैं।
- **One-shot bugs** – Expanded window (tens of microseconds से minutes तक) CPU affinity pinning या hypervisor-assisted preemption के साथ paired होने पर “single trigger” bugs को realistic बनाती है।
- **Side effects** – Slowdown केवल malicious path को प्रभावित करता है, इसलिए overall system performance अप्रभावित रहती है; defenders को इसका पता शायद ही चले, जब तक वे namespace growth monitor न करें।
- **Cleanup** – आपके द्वारा बनाए गए प्रत्येक directory/object के handles बनाए रखें, ताकि बाद में `NtMakeTemporaryObject`/`NtClose` call कर सकें। अन्यथा unbounded directory chains reboots के बाद भी बनी रह सकती हैं।
- **File-system races** – यदि vulnerable path अंततः NTFS के माध्यम से resolve होता है, तो OM slowdown चलने के दौरान backing file पर एक Oplock (जैसे उसी toolkit का `SetOpLock.exe`) stack कर सकते हैं, जिससे OM graph बदले बिना consumer को अतिरिक्त milliseconds के लिए freeze किया जा सके।<sup>[[2]](#references)</sup>

## Defensive notes

- Named objects पर निर्भर Kernel code को open के *बाद* security-sensitive state को फिर से validate करना चाहिए, या check से पहले reference लेना चाहिए (TOCTOU gap को बंद करने के लिए)।
- User-controlled names को dereference करने से पहले OM path depth/length पर upper bounds लागू करें। अत्यधिक लंबे names को reject करने से attackers microsecond window में वापस सीमित हो जाते हैं।
- Suspicious thousands-of-components chains का पता लगाने के लिए `\BaseNamedObjects` के अंतर्गत Object Manager namespace growth को instrument करें (ETW `Microsoft-Windows-Kernel-Object`)।

## References

- [1] [Project Zero – Windows Exploitation Techniques: Path Lookups के साथ Race Conditions जीतना](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
