# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## रेस विंडो को बढ़ाना क्यों मायने रखता है

कई Windows kernel LPEs पारंपरिक पैटर्न का पालन करते हैं `check_state(); NtOpenX("name"); privileged_action();`. आधुनिक हार्डवेयर पर एक कोल्ड `NtOpenEvent`/`NtOpenSection` लगभग 2 µs में एक short name को resolve कर देता है, जिससे checked state को flip करने के लिए लगभग कोई समय नहीं बचता। चरण 2 में Object Manager Namespace (OMNS) lookup को जानबूझकर कई दस माइक्रोसेकंड तक धीमा करके, attacker के पास फ्लेकी रेसेस में लगातार जीतने के लिए पर्याप्त समय आ जाता है बिना हजारों प्रयासों की आवश्यकता के।

## Object Manager lookup की आंतरिक जानकारी संक्षेप में

* **OMNS structure** – `\BaseNamedObjects\Foo` जैसे नाम directory-by-directory हल होते हैं। हर component kernel को एक *Object Directory* ढूँढने/खोलने और Unicode strings की तुलना करने पर मजबूर करता है। Symbolic links (उदा., ड्राइव लेटर्स) रास्ते में ट्रैवर्स किए जा सकते हैं।
* **UNICODE_STRING limit** – OM paths `UNICODE_STRING` के अंदर रखे जाते हैं जिसका `Length` एक 16-bit मान है। पूर्ण सीमा 65 535 bytes (32 767 UTF-16 codepoints) है। `\BaseNamedObjects\` जैसे prefixes के साथ attacker के पास अभी भी ≈32 000 characters नियंत्रित करने की क्षमता रहती है।
* **Attacker prerequisites** – कोई भी user writable directories जैसे `\BaseNamedObjects` के नीचे objects बना सकता है। जब vulnerable code उस अंदर के किसी नाम का उपयोग करता है, या कोई symbolic link follow करता है जो वहां land करता है, तो attacker बिना किसी विशेष privileges के lookup performance को नियंत्रित कर सकता है।

## Slowdown primitive #1 – Single maximal component

किसी component को resolve करने की लागत मोटे तौर पर उसकी लंबाई के साथ रैखिक होती है क्योंकि kernel को parent directory के हर entry के साथ एक Unicode comparison करना पड़ता है। 32 kB लंबा नाम वाले event को बनाने से `NtOpenEvent` latency तुरंत लगभग ~2 µs से बढ़कर ~35 µs हो जाती है Windows 11 24H2 (Snapdragon X Elite testbed) पर।
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*व्यावहारिक नोट्स*

- आप किसी भी named kernel object (events, sections, semaphores…) का उपयोग करके लंबाई सीमा तक पहुंच सकते हैं।
- Symbolic links या reparse points एक छोटे 'victim' नाम को इस giant component की ओर इंगित कर सकते हैं ताकि slowdown पारदर्शी रूप से लागू हो।
- चूँकि सब कुछ user-writable namespaces में रहता है, payload एक standard user integrity level से काम करता है।

## Slowdown primitive #2 – Deep recursive directories

एक और अधिक आक्रामक variant हज़ारों directories की एक श्रृंखला बनाता है (`\BaseNamedObjects\A\A\...\X`)। प्रत्येक hop directory resolution logic (ACL checks, hash lookups, reference counting) को trigger करता है, इसलिए per-level latency एक single string compare की तुलना में अधिक होती है। ~16 000 levels (limited by the same `UNICODE_STRING` size) के साथ, प्रायोगिक टाइमिंग्स long single components द्वारा प्राप्त 35 µs बाधा को पार कर जाती हैं।
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

* यदि मूल निर्देशिका डुप्लिकेट अस्वीकार करना शुरू कर दे तो प्रति-स्तर character बदलते रहें (`A/B/C/...`)
* एक handle array रखें ताकि आप exploitation के बाद chain को साफ़ तरीके से हटाकर namespace को प्रदूषित होने से बचा सकें।

## अपनी race window का मापन

अपने exploit के अंदर एक छोटा harness एम्बेड करें ताकि यह मापा जा सके कि टार्गेट हार्डवेयर पर window कितना बड़ा होता है। नीचे दिया गया स्निपेट target object को `iterations` बार खोलता है और `QueryPerformanceCounter` का उपयोग करके प्रति-ओपन औसत लागत लौटाता है।
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

## एक्सप्लॉइटेशन वर्कफ़्लो

1. **Locate the vulnerable open** – kernel path को ट्रेस करें (via symbols, ETW, hypervisor tracing, या reversing) जब तक आपको कोई `NtOpen*`/`ObOpenObjectByName` कॉल न मिल जाए जो हमलावर-नियंत्रित नाम या user-writable directory में symbolic link को walk करे।
2. **Replace that name with a slow path**
- `\BaseNamedObjects` (या किसी दूसरे writable OM root) के अंतर्गत लंबा component या directory chain बनाएं।
- एक symbolic link बनाएं ताकि kernel जिस नाम की उम्मीद करता है वह अब slow path पर resolve हो। आप vulnerable driver के directory lookup को अपने structure की ओर point कर सकते हैं बिना original target को छुए।
3. **Trigger the race**
- Thread A (victim) vulnerable कोड चलाती है और slow lookup के अंदर block हो जाती है।
- Thread B (attacker) guarded state को flip करता/करती है (उदा., एक file handle swap करना, symbolic link को rewrite करना, object security toggle करना) जबकि Thread A व्यस्त है।
- जब Thread A resume होती है और privileged action करती है, तो वह stale state देखती है और attacker-controlled operation करती है।
4. **Clean up** – संदिग्ध artifacts छोड़ने या legitimate IPC users को प्रभावित करने से बचने के लिए directory chain और symbolic links हटा दें।

## संचालन संबंधी विचार

- **Combine primitives** – आप directory chain में प्रत्येक स्तर (*per level*) पर लंबा नाम उपयोग कर सकते हैं ताकि latency और बढ़े, जब तक कि आप `UNICODE_STRING` size को exhaust न कर दें।
- **One-shot bugs** – विस्तारित विंडो (दसियों माइक्रोसेकंड) single trigger bugs को realistic बनाती है जब इसे CPU affinity pinning या hypervisor-assisted preemption के साथ जोड़ा जाए।
- **Side effects** – slowdown केवल malicious path को प्रभावित करती है, इसलिए समग्र सिस्टम प्रदर्शन अप्रभावित रहता है; defenders आमतौर पर तब तक नोटिस नहीं करेंगे जब तक वे namespace growth की निगरानी न कर रहे हों।
- **Cleanup** – आपने जो भी directory/object बनाए हैं उनके handles रखें ताकि आप बाद में `NtMakeTemporaryObject`/`NtClose` कॉल कर सकें। अन्यथा अनबाउंडेड directory chains reboots के बाद भी बनी रह सकती हैं।

## रक्षात्मक नोट्स

- नामित objects पर निर्भर kernel कोड को open के *बाद* security-sensitive state को फिर से validate करना चाहिए, या check से पहले reference लेना चाहिए (TOCTOU gap को बंद करना)।
- user-controlled नामों को dereference करने से पहले OM path की depth/length पर upper bounds लागू करें। बहुत लंबे नामों को reject करने से attackers को फिर से microsecond विंडो में सीमित किया जाता है।
- object manager namespace वृद्धि को instrument करें (ETW `Microsoft-Windows-Kernel-Object`) ताकि `\BaseNamedObjects` के अंतर्गत suspicious thousands-of-components chains का पता लगाया जा सके।

## संदर्भ

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
