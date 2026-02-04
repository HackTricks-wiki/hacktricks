# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Why stretching the race window matters

बहुत से Windows kernel LPEs क्लासिक पैटर्न `check_state(); NtOpenX("name"); privileged_action();` का पालन करते हैं। आधुनिक हार्डवेयर पर एक cold `NtOpenEvent`/`NtOpenSection` एक छोटा नाम ~2 µs में resolve कर देता है, जिससे secure action होने से पहले checked state flip करने के लिए लगभग कोई समय नहीं बचता। कदम 2 में Object Manager Namespace (OMNS) lookup को जानबूझकर कुछ दसियों माइक्रोसेकंड तक खींचकर, attacker के पास पहले से flaky races में लगातार जीतने के लिए पर्याप्त समय आ जाता है बिना हज़ारों कोशिशों के ज़रूरत पड़े।

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Names such as `\BaseNamedObjects\Foo` directory-by-directory resolve होते हैं। हर component kernel को एक *Object Directory* ढूँढने/खोलने और Unicode strings की तुलना करने पर मजबूर करता है। Symbolic links (e.g., drive letters) रास्ते में पार किए जा सकते हैं।
* **UNICODE_STRING limit** – OM paths एक `UNICODE_STRING` के अंदर होते हैं जिसका `Length` 16-bit मान है। absolute limit 65 535 bytes (32 767 UTF-16 codepoints) है। `\BaseNamedObjects\` जैसे prefixes के साथ भी attacker लगभग 32 000 characters नियंत्रित कर सकता है।
* **Attacker prerequisites** – कोई भी user writable directories जैसे `\BaseNamedObjects` के नीचे objects बना सकता है। जब vulnerable code इनमे से किसी नाम का उपयोग करता है, या किसी symbolic link को follow करता है जो वहां land करता है, तो attacker बिना किसी विशेष privileges के lookup performance नियंत्रित कर सकता है।

## Slowdown primitive #1 – Single maximal component

किसी component को resolve करने की लागत उसकी लंबाई के साथ मोटे तौर पर linear होती है क्योंकि kernel को parent directory की हर entry के खिलाफ Unicode comparison करना पड़ता है। 32 kB लंबे नाम के साथ एक event बनाने से `NtOpenEvent` की latency तुरंत ~2 µs से बढ़कर ~35 µs हो जाती है (Windows 11 24H2, Snapdragon X Elite testbed)।
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
- Symbolic links या reparse points छोटे “victim” नाम को इस giant component की ओर इंगित कर सकते हैं ताकि slowdown पारदर्शी रूप से लागू हो।
- क्योंकि सब कुछ user-writable namespaces में रहता है, payload एक standard user integrity level से काम करता है।

## Slowdown primitive #2 – Deep recursive directories

एक अधिक aggressive variant हजारों directories की एक chain allocate करता है (`\BaseNamedObjects\A\A\...\X`)। हर hop directory resolution logic (ACL checks, hash lookups, reference counting) को trigger करता है, इसलिए प्रति-स्तर latency एक single string compare से अधिक होता है। ~16 000 levels के साथ (जिसे वही `UNICODE_STRING` size सीमित करता है), empirical timings लंबी single components से प्राप्त 35 µs बाधा को पार कर जाती हैं।
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

* यदि parent directory डुप्लिकेट अस्वीकार करने लगे तो हर लेवल पर कैरेक्टर बदलें (`A/B/C/...`)।
* एक handle array रखें ताकि आप exploitation के बाद chain को साफ़-सुथरा हटाकर namespace को प्रदूषित होने से बचा सकें।

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories support **shadow directories** (fallback lookups) and bucketed hash tables for entries. Abuse both plus the 64-component symbolic-link reparse limit to multiply slowdown without exceeding the `UNICODE_STRING` length:

1. `\BaseNamedObjects` के अंतर्गत दो directories बनाएँ, जैसे `A` (shadow) और `A\A` (target)। दूसरी directory को पहले वाले को shadow directory के रूप में उपयोग करके बनाएँ (`NtCreateDirectoryObjectEx`), ताकि `A` में missing lookups `A\A` पर fall through हों।
2. प्रत्येक directory को हजारों **colliding names** से भरें जो एक ही hash bucket में land करें (उदा., trailing digits बदलते हुए और वही `RtlHashUnicodeString` value बनाए रखें)। अब lookups एक single directory के अंदर O(n) linear scans में degrade हो जाती हैं।
3. लगभग 63 की chain बनाएं जो **object manager symbolic links** हों और बार-बार long `A\A\…` suffix में reparse करें, जिससे reparse budget खर्च होता है। हर reparse parsing को ऊपर से restart कर देता है, जिससे collision cost गुणा हो जाता है।
4. अंतिम component (`...\\0`) का lookup अब Windows 11 पर तब **minutes** लेता है जब हर directory में 16 000 collisions मौजूद हों, जो one-shot kernel LPEs के लिए व्यावहारिक रूप से सुनिश्चित race जीत प्रदान करता है।
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*क्यों यह मायने रखता है*: कई मिनटों का slowdown one-shot race-based LPEs को deterministic exploits में बदल देता है।

## अपनी race window को मापना

अपनी exploit के अंदर एक छोटा harness एम्बेड करें ताकि यह मापा जा सके कि victim hardware पर window कितना बड़ा हो जाता है। नीचे दिया गया snippet लक्ष्य ऑब्जेक्ट को `iterations` बार खोलता है और `QueryPerformanceCounter` का उपयोग करके प्रति-ओपन औसत लागत लौटाता है।
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
The results feed directly into your race orchestration strategy (e.g., number of worker threads needed, sleep intervals, how early you need to flip the shared state).

## Exploitation workflow

1. **Locate the vulnerable open** – कर्नेल path को ट्रेस करें (via symbols, ETW, hypervisor tracing, or reversing) जब तक आप `NtOpen*`/`ObOpenObjectByName` कॉल न पाएँ जो attacker-controlled name या user-writable directory में किसी symbolic link को walk करता हो।
2. **Replace that name with a slow path**
- `\BaseNamedObjects` (या किसी अन्य writable OM root) के अंतर्गत लंबा component या directory chain बनाएँ।
- एक symbolic link बनाएँ ताकि कर्नेल जो नाम अपेक्षित करता है वह अब slow path पर resolve हो। आप vulnerable driver के directory lookup को अपने structure की ओर point कर सकते हैं बिना original target को छुए।
3. **Trigger the race**
- Thread A (victim) vulnerable code को execute करता है और slow lookup के अंदर block हो जाता है।
- Thread B (attacker) guarded state को flip करता है (उदा., एक file handle swap करना, symbolic link को rewrite करना, object security toggle करना) जबकि Thread A व्यस्त है।
- जब Thread A resume करता है और privileged action करता है, तो वह stale state देखता है और attacker-controlled operation कर देता है।
4. **Clean up** – directory chain और symbolic links को delete करें ताकि suspicious artifacts न बचें या legitimate IPC users बाधित न हों।

## Operational considerations

- **Combine primitives** – आप directory chain में प्रति स्तर लंबा नाम (*per level*) इस्तेमाल कर सकते हैं ताकि latency और बढ़े, जब तक कि आप `UNICODE_STRING` size को exhaust न कर दें।
- **One-shot bugs** – विस्तारित विंडो (tens of microseconds से minutes) “single trigger” bugs को realistic बनाती है जब इसे CPU affinity pinning या hypervisor-assisted preemption के साथ जोड़ा जाये।
- **Side effects** – slowdown केवल malicious path को प्रभावित करता है, इसलिए समग्र सिस्टम प्रदर्शन अप्रभावित रहता है; defenders अक्सर तब तक ध्यान नहीं देंगे जब तक वे namespace growth को monitor न कर रहे हों।
- **Cleanup** – आपने जो भी directory/object बनाए हैं उनके handles रखें ताकि आप बाद में `NtMakeTemporaryObject`/`NtClose` कॉल कर सकें। अन्यथा अनबाउंडेड directory chains reboots के बाद बने रह सकते हैं।

## Defensive notes

- named objects पर निर्भर kernel code को open के बाद security-sensitive state को पुनः-मान्य (re-validate) करना चाहिए, या जांच से पहले reference लेना चाहिए (TOCTOU gap को बंद करते हुए)।
- user-controlled names को dereference करने से पहले OM path की depth/length पर upper bounds लागू करें। अत्यधिक लंबे नाम reject करने से attackers को microsecond विंडो में वापस लाया जा सकता है।
- object manager namespace growth को instrument करें (ETW `Microsoft-Windows-Kernel-Object`) ताकि `\BaseNamedObjects` के तहत suspicious हजारों-components वाले chains का पता लग सके।

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
