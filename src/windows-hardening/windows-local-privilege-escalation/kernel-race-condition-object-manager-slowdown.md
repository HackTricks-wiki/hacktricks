# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## रेस विंडो बढ़ाने का महत्व

कई Windows kernel LPEs क्लासिक पैटर्न का पालन करते हैं `check_state(); NtOpenX("name"); privileged_action();`. आधुनिक हार्डवेयर पर एक cold `NtOpenEvent`/`NtOpenSection` छोटे नाम को ~2 µs में रिज़ॉल्व कर देता है, जिससे चेक किए गए state को secure action से पहले पलटने के लिए लगभग कोई समय नहीं बचता। चरण 2 में जानबूझकर Object Manager Namespace (OMNS) lookup को दसियों माइक्रोसेकंड तक खींचकर, आक्रमणकर्ता के पास पर्याप्त समय आ जाता है ताकि वे अन्यथा flaky races में लगातार जीत सकें बिना हजारों प्रयास करने के।

## Object Manager lookup के आंतरिक विवरण संक्षेप में

* **OMNS structure** – Names such as `\BaseNamedObjects\Foo` directory-by-directory resolve होते हैं। प्रत्येक component kernel को एक *Object Directory* खोजने/खोलने और Unicode strings की तुलना करने के लिए मजबूर करता है। मार्ग में symbolic links (उदा., drive letters) भी traverse हो सकते हैं।
* **UNICODE_STRING limit** – OM paths `UNICODE_STRING` के अंदर रखे जाते हैं जिसका `Length` 16-bit मान है। Absolute limit 65 535 bytes (32 767 UTF-16 codepoints) है। `\BaseNamedObjects\` जैसे prefixes के साथ, एक आक्रमणकर्ता अभी भी लगभग 32 000 characters नियंत्रित कर सकता है।
* **Attacker prerequisites** – कोई भी user writable directories जैसे `\BaseNamedObjects` के अंदर objects बना सकता है। जब vulnerable code वहाँ के किसी name का उपयोग करता है, या ऐसा symbolic link follow करता है जो वहीं land करता है, तो आक्रमणकर्ता बिना किसी विशेष privileges के lookup performance नियंत्रित कर सकता है।

## Slowdown primitive #1 – Single maximal component

किसी component को resolve करने की लागत इसकी लंबाई के साथ लगभग linear होती है क्योंकि kernel को parent directory में हर entry के खिलाफ एक Unicode comparison करना पड़ता है। एक event को 32 kB लंबा नाम देकर बनाना `NtOpenEvent` की latency को तुरंत ~2 µs से बढ़ाकर ~35 µs कर देता है Windows 11 24H2 (Snapdragon X Elite testbed) पर।
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*व्यवहारिक नोट्स*

- आप किसी भी named kernel object (events, sections, semaphores…) का उपयोग करके length limit हिट कर सकते हैं।
- Symbolic links or reparse points छोटे “victim” नाम को इस giant component की ओर पॉइंट कर सकते हैं ताकि slowdown पारदर्शी रूप से लागू हो।
- चूंकि सबकुछ user-writable namespaces में रहता है, payload standard user integrity level से काम करता है।

## Slowdown primitive #2 – Deep recursive directories

एक अधिक aggressive variant हजारों डायरेक्टरीज़ की एक chain allocate करता है (`\BaseNamedObjects\A\A\...\X`). हर hop directory resolution logic (ACL checks, hash lookups, reference counting) को trigger करता है, इसलिए प्रति-स्तर latency एक single string compare की तुलना में अधिक है। With ~16 000 levels (limited by the same `UNICODE_STRING` size), empirical timings लंबे single components द्वारा प्राप्त 35 µs barrier को पार कर जाते हैं।
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
टिप्स:

* यदि parent directory डुप्लिकेट reject करना शुरू कर दे तो प्रति स्तर character बदलते रहें (`A/B/C/...`)।
* Keep a handle array ताकि आप exploitation के बाद chain को cleanly delete कर सकें और namespace को pollute होने से रोक सकें।

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories support **shadow directories** (fallback lookups) and bucketed hash tables for entries. इन दोनों का miss-use करें और 64-component symbolic-link reparse limit का उपयोग करके slowdown को गुणा करें बिना `UNICODE_STRING` length को exceed किए:

1. `\BaseNamedObjects` के अंतर्गत दो directories बनाएं, जैसे `A` (shadow) और `A\A` (target). दूसरे को पहले को shadow directory के रूप में उपयोग करके बनाएं (`NtCreateDirectoryObjectEx`), ताकि `A` में missing lookups `A\A` में fall through कर जाएँ।
2. हर directory को हजारों **colliding names** से भरें जो उसी hash bucket में land करते हों (उदाहरण के लिए trailing digits बदलें जबकि वही `RtlHashUnicodeString` value रखें). अब lookups एक single directory के अंदर O(n) linear scans तक degrade हो जाते हैं।
3. लगभग ~63 की chain बनाएं जिसमें **object manager symbolic links** बार-बार लंबी `A\A\…` suffix में reparse हों और reparse budget को consume कर दें। हर reparse parsing को ऊपर से restart करता है, जिससे collision cost गुणा हो जाती है।
4. जब प्रति directory 16 000 collisions मौजूद हों तो final component (`...\\0`) का lookup अब Windows 11 पर **minutes** लेता है, जो one-shot kernel LPEs के लिए व्यवहारिक रूप से सुनिश्चित race जीत प्रदान करता है।
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*क्यों यह महत्वपूर्ण है*: मिनटों तक चलने वाली धीमी स्थिति one-shot race-based LPEs को deterministic exploits में बदल देती है।

### 2025 रिटेस्ट नोट्स & रेडी-मेड टूलिंग

- James Forshaw ने technique को Windows 11 24H2 (ARM64) पर updated timings के साथ पुनर्प्रकाशित किया। बेसलाइन opens लगभग ~2 µs ही रहते हैं; एक 32 kB component इसे ~35 µs तक बढ़ा देता है, और shadow-dir + collision + 63-reparse chains अभी भी ~3 minutes तक पहुँचती हैं, जिससे पुष्टि होती है कि primitives वर्तमान बिल्ड्स में भी टिके हुए हैं। Source code और perf harness refreshed Project Zero post में मौजूद हैं।
- आप public `symboliclink-testing-tools` bundle का उपयोग करके setup को script कर सकते हैं: `CreateObjectDirectory.exe` shadow/target pair को spawn करने के लिए और `NativeSymlink.exe` को loop में चलाकर 63-hop chain emit करने के लिए। यह hand-written `NtCreate*` wrappers की ज़रूरत से बचाता है और ACLs को consistent रखता है।

## अपने race window को मापना

अपने exploit के भीतर एक त्वरित harness embed करें ताकि मापा जा सके कि विंडो लक्ष्य हार्डवेयर पर कितनी बड़ी होती है। नीचे दिया गया snippet लक्ष्य object को `iterations` बार खोलता है और `QueryPerformanceCounter` का उपयोग करके average प्रति-ओपन लागत लौटाता है।
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

1. **Locate the vulnerable open** – कर्नेल पथ को ट्रेस करें (symbols, ETW, hypervisor tracing, या reversing के माध्यम से) जब तक आपको ऐसा कोई `NtOpen*`/`ObOpenObjectByName` कॉल न मिल जाए जो attacker-controlled नाम या user-writable डायरेक्टरी में मौजूद symbolic link को वॉक करता हो।
2. **Replace that name with a slow path**
- `\BaseNamedObjects` (या किसी अन्य writable OM root) के अंतर्गत लंबी component या directory chain बनाएं।
- एक symbolic link बनाएं ताकि वह नाम जिसे कर्नेल उम्मीद करता है, अब slow path पर resolve हो जाए। आप vulnerable driver के directory lookup को बिना मूल लक्ष्य को छुए अपनी संरचना की ओर निर्देशित कर सकते हैं।
3. **Trigger the race**
- Thread A (victim) vulnerable कोड को execute करता है और slow lookup के अंदर block हो जाता है।
- Thread B (attacker) guarded state को flip करता है (उदाहरण के लिए, कोई file handle swap करना, एक symbolic link को फिर से लिखना, या object security toggle करना) जबकि Thread A व्यस्त है।
- जब Thread A resume होकर privileged action करता है, तो वह stale state देखता है और attacker-controlled operation को निष्पादित कर देता है।
4. **Clean up** – संदिग्ध artifacts छोड़ने या legitimate IPC users को प्रभावित करने से बचने के लिए directory chain और symbolic links हटाएं।

## Operational considerations

- **Combine primitives** – आप directory chain में प्रति स्तर लंबा नाम (`per level`) उपयोग कर सकते हैं ताकि latency और बढ़े, जब तक कि आप `UNICODE_STRING` size को exhaust न कर दें।
- **One-shot bugs** – विस्तारित विंडो (tens of microseconds से minutes तक) “single trigger” बग को वास्तविक बनाती है, खासकर जब इसे CPU affinity pinning या hypervisor-assisted preemption के साथ जोड़ा जाए।
- **Side effects** – slowdown केवल malicious path को प्रभावित करता है, इसलिए पूरे सिस्टम का प्रदर्शन प्रभावित नहीं होता; defenders सामान्यतः तब ही नोटिस करेंगे जब वे namespace growth को मॉनिटर करते हों।
- **Cleanup** – आपने जो भी directory/object बनाए हैं उनके हैंडल रखें ताकि आप बाद में `NtMakeTemporaryObject`/`NtClose` कॉल कर सकें। अन्यथा unbounded directory chains reboots के बाद भी बनी रह सकती हैं।
- **File-system races** – यदि vulnerable path अंततः NTFS के माध्यम से resolve होता है, तो आप backing file पर एक Oplock (उदाहरण के लिए, `SetOpLock.exe` उसी toolkit से) डाल सकते हैं जबकि OM slowdown चल रहा हो, जिससे consumer कुछ अतिरिक्त milliseconds के लिए freeze हो जाएगा बिना OM graph को बदले।

## Defensive notes

- named objects पर निर्भर kernel कोड को open के बाद security-sensitive state को re-validate करना चाहिए, या check से पहले reference लेनी चाहिए (TOCTOU gap को बंद करते हुए)।
- user-controlled नामों को dereference करने से पहले OM path की depth/length पर upper bounds लागू करें। अत्यधिक लंबे नामों को reject करने से attackers को microsecond विंडो में वापस धकेला जाएगा।
- object manager namespace growth (ETW `Microsoft-Windows-Kernel-Object`) को instrument करें ताकि `\BaseNamedObjects` के अंतर्गत suspicious हजारों components वाली chains का पता चल सके।

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
