# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Race window को बढ़ाना क्यों महत्वपूर्ण है

कई Windows kernel LPEs क्लासिक पैटर्न `check_state(); NtOpenX("name"); privileged_action();` का पालन करते हैं। आधुनिक hardware पर एक cold `NtOpenEvent`/`NtOpenSection` लगभग 2 µs में short name को resolve कर लेता है, जिससे secure action होने से पहले checked state को बदलने के लिए लगभग कोई समय नहीं बचता। Step 2 में Object Manager Namespace (OMNS) lookup को जानबूझकर tens of microseconds तक चलने के लिए मजबूर करके, attacker को पर्याप्त समय मिल जाता है और हजारों attempts की आवश्यकता के बिना अन्यथा flaky races को लगातार जीतना संभव हो जाता है।<sup>[[1]](#references)</sup>

## Object Manager lookup internals संक्षेप में

* **OMNS structure** – `\BaseNamedObjects\Foo` जैसे names को directory-by-directory resolve किया जाता है। प्रत्येक component के कारण kernel को एक *Object Directory* को find/open करना और Unicode strings की तुलना करनी पड़ती है। रास्ते में symbolic links (जैसे drive letters) को traverse किया जा सकता है।
* **UNICODE_STRING limit** – OM paths को एक `UNICODE_STRING` के अंदर रखा जाता है, जिसका `Length` value 16-bit होती है। Absolute limit 65 535 bytes (32 767 UTF-16 codepoints) है। `\BaseNamedObjects\` जैसे prefixes के साथ भी attacker के नियंत्रण में लगभग 32 000 characters रहते हैं।
* **Attacker prerequisites** – कोई भी user `\BaseNamedObjects` जैसी writable directories के अंदर objects create कर सकता है। जब vulnerable code इसके अंदर मौजूद name का उपयोग करता है या ऐसी symbolic link को follow करता है जो वहाँ पहुँचती है, तो attacker बिना किसी special privileges के lookup performance को नियंत्रित कर सकता है।<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Single maximal component

किसी component को resolve करने की cost उसकी length के साथ लगभग linear होती है, क्योंकि kernel को parent directory की प्रत्येक entry के विरुद्ध Unicode comparison करनी पड़ती है। 32 kB-long name वाला event create करने से Windows 11 24H2 (Snapdragon X Elite testbed) पर `NtOpenEvent` latency लगभग 2 µs से बढ़कर ~35 µs हो जाती है।
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*व्यावहारिक नोट्स*

- आप किसी भी named kernel object (events, sections, semaphores…) का उपयोग करके length limit तक पहुँच सकते हैं।
- Symbolic links या reparse points किसी छोटे “victim” नाम को इस giant component की ओर point कर सकते हैं, जिससे slowdown transparently लागू होता है।
- क्योंकि सब कुछ user-writable namespaces में रहता है, payload standard user integrity level से काम करता है।<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Deep recursive directories

एक अधिक aggressive variant हजारों directories की chain (`\BaseNamedObjects\A\A\...\X`) allocate करता है। हर hop directory resolution logic (ACL checks, hash lookups, reference counting) को trigger करता है, इसलिए per-level latency single string compare की तुलना में अधिक होती है। ~16 000 levels (उसी `UNICODE_STRING` size द्वारा सीमित) के साथ, empirical timings long single components द्वारा प्राप्त 35 µs barrier को पार कर जाती हैं।
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
सुझाव:

* यदि parent directory duplicates को reject करना शुरू कर दे, तो हर level पर character (`A/B/C/...`) बदलें।
* एक handle array रखें, ताकि exploitation के बाद chain को साफ़ तरीके से delete किया जा सके और namespace प्रदूषित न हो।<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions और symlink reparses (microseconds के बजाय minutes)

Object directories **shadow directories** (fallback lookups) और entries के लिए bucketed hash tables को support करती हैं। दोनों का abuse करें और `UNICODE_STRING` length बढ़ाए बिना slowdown को कई गुना करने के लिए 64-component symbolic-link reparse limit का उपयोग करें:

1. `\BaseNamedObjects` के अंतर्गत दो directories बनाएँ, जैसे `A` (shadow) और `A\A` (target)। पहली directory को shadow directory के रूप में उपयोग करके (`NtCreateDirectoryObjectEx`) दूसरी directory बनाएँ, ताकि `A` में missing lookups `A\A` पर fall through हों।
2. प्रत्येक directory को ऐसे हजारों **colliding names** से भरें जो उसी hash bucket में जाएँ (जैसे trailing digits बदलते हुए भी वही `RtlHashUnicodeString` value बनाए रखें)। अब lookups एक ही directory के अंदर O(n) linear scans तक degrade हो जाएँगे।
3. लगभग 63 **object manager symbolic links** की chain बनाएँ, जो बार-बार लंबे `A\A\…` suffix में reparse हों और reparse budget को consume करें। प्रत्येक reparse parsing को ऊपर से फिर शुरू करता है, जिससे collision cost कई गुना बढ़ जाती है।
4. अब final component (`...\\0`) का lookup Windows 11 पर minutes लेता है, जब प्रत्येक directory में 16 000 collisions मौजूद हों। इससे one-shot kernel LPEs के लिए practically guaranteed race win मिलता है।
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*क्यों महत्वपूर्ण है*: कुछ मिनटों का slowdown one-shot race-based LPEs को deterministic exploits में बदल देता है.<sup>[[1]](#references)</sup>

### 2025 के retest notes और ready-made tooling

- James Forshaw ने Windows 11 24H2 (ARM64) पर updated timings के साथ technique को फिर से प्रकाशित किया। Baseline opens की लागत ~2 µs बनी रहती है; 32 kB component इसे ~35 µs तक बढ़ा देता है, और shadow-dir + collision + 63-reparse chains अब भी ~3 minutes तक पहुँचती हैं, जिससे पुष्टि होती है कि primitives वर्तमान builds में भी काम करते हैं। Source code और perf harness refreshed Project Zero post में हैं।<sup>[[1]](#references)</sup>
- आप public `symboliclink-testing-tools` bundle का उपयोग करके setup को script कर सकते हैं: shadow/target pair बनाने के लिए `CreateObjectDirectory.exe` और 63-hop chain बनाने के लिए loop में `NativeSymlink.exe` चलाएँ। इससे hand-written `NtCreate*` wrappers की आवश्यकता नहीं रहती और ACLs consistent रहते हैं।<sup>[[2]](#references)</sup>

## अपनी race window को मापना

अपने exploit में एक quick harness शामिल करें, ताकि victim hardware पर window के आकार को मापा जा सके। नीचे दिया गया snippet target object को `iterations` बार खोलता है और `QueryPerformanceCounter` का उपयोग करके प्रति-open average cost लौटाता है।<sup>[[1]](#references)</sup>
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
परिणाम सीधे आपकी race orchestration strategy में उपयोग होते हैं (जैसे, आवश्यक worker threads की संख्या, sleep intervals, और shared state को कितनी जल्दी flip करना है)।

## Exploitation workflow

1. **Vulnerable open का पता लगाएँ** – symbols, ETW, hypervisor tracing या reversing के माध्यम से kernel path को trace करें, जब तक आपको ऐसा `NtOpen*`/`ObOpenObjectByName` call न मिल जाए जो attacker-controlled name या user-writable directory में symbolic link को traverse करता हो।
2. **उस name को slow path से बदलें**
- `\BaseNamedObjects` (या किसी अन्य writable OM root) के अंतर्गत long component या directory chain बनाएँ।
- एक symbolic link बनाएँ ताकि kernel द्वारा अपेक्षित name अब slow path पर resolve हो। आप original target को छुए बिना vulnerable driver के directory lookup को अपनी structure पर point कर सकते हैं।
3. **Race को trigger करें**
- Thread A (victim) vulnerable code execute करता है और slow lookup के अंदर block हो जाता है।
- Thread B (attacker) guarded state को flip करता है (जैसे, file handle swap करना, symbolic link को rewrite करना, या object security को toggle करना), जबकि Thread A व्यस्त है।
- जब Thread A resume होकर privileged action करता है, तो उसे stale state दिखाई देती है और वह attacker-controlled operation perform करता है।
4. **Cleanup करें** – suspicious artifacts छोड़ने या legitimate IPC users को बाधित करने से बचने के लिए directory chain और symbolic links को delete करें।<sup>[[1]](#references)</sup>

## Operational considerations

- **Primitives को combine करें** – और भी अधिक latency के लिए directory chain में *प्रत्येक level* पर long name का उपयोग कर सकते हैं, जब तक `UNICODE_STRING` size समाप्त न हो जाए।
- **One-shot bugs** – विस्तारित window (दसियों microseconds से minutes तक) CPU affinity pinning या hypervisor-assisted preemption के साथ मिलकर “single trigger” bugs को realistic बनाती है।
- **Side effects** – slowdown केवल malicious path को प्रभावित करता है, इसलिए overall system performance अप्रभावित रहती है; defenders इसे शायद ही notice करेंगे, जब तक वे namespace growth monitor न करें।
- **Cleanup** – अपने द्वारा बनाए गए प्रत्येक directory/object के handles रखें, ताकि बाद में `NtMakeTemporaryObject`/`NtClose` call कर सकें। अन्यथा unbounded directory chains reboot के बाद भी persist कर सकती हैं।
- **File-system races** – यदि vulnerable path अंततः NTFS के माध्यम से resolve होता है, तो OM slowdown के दौरान backing file पर Oplock (जैसे, उसी toolkit का `SetOpLock.exe`) stack कर सकते हैं। इससे OM graph को बदले बिना consumer को अतिरिक्त milliseconds के लिए freeze किया जा सकता है।<sup>[[2]](#references)</sup>

## Defensive notes

- Named objects पर निर्भर kernel code को open के *बाद* security-sensitive state को फिर से validate करना चाहिए, या check से पहले reference लेना चाहिए (TOCTOU gap को बंद करने के लिए)।
- User-controlled names को dereference करने से पहले OM path depth/length पर upper bounds लागू करें। अत्यधिक लंबे names को reject करने से attackers फिर से microsecond window तक सीमित हो जाते हैं।
- Object manager namespace growth को instrument करें (ETW `Microsoft-Windows-Kernel-Object`), ताकि `\BaseNamedObjects` के अंतर्गत suspicious thousands-of-components chains का पता लगाया जा सके।

## References

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
