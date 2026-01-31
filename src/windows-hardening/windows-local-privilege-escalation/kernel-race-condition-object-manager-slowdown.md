# Object Manager Slow Paths के जरिए Kernel Race Condition का शोषण

{{#include ../../banners/hacktricks-training.md}}

## Why stretching the race window matters

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. On modern hardware a cold `NtOpenEvent`/`NtOpenSection` resolves a short name in ~2 µs, leaving almost no time to flip the checked state before the secure action happens. By deliberately forcing the Object Manager Namespace (OMNS) lookup in step 2 to take tens of microseconds, the attacker gains enough time to consistently win otherwise flaky races without needing thousands of attempts.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Names such as `\BaseNamedObjects\Foo` are resolved directory-by-directory. Each component causes the kernel to find/open an *Object Directory* and compare Unicode strings. Symbolic links (e.g., drive letters) may be traversed en route.
* **UNICODE_STRING limit** – OM paths are carried inside a `UNICODE_STRING` whose `Length` is a 16-bit value. The absolute limit is 65 535 bytes (32 767 UTF-16 codepoints). With prefixes like `\BaseNamedObjects\`, an attacker still controls ≈32 000 characters.
* **Attacker prerequisites** – Any user can create objects underneath writable directories such as `\BaseNamedObjects`. When the vulnerable code uses a name inside, or follows a symbolic link that lands there, the attacker controls the lookup performance with no special privileges.

## Slowdown primitive #1 – Single maximal component

The cost of resolving a component is roughly linear with its length because the kernel must perform a Unicode comparison against every entry in the parent directory. Creating an event with a 32 kB-long name immediately increases the `NtOpenEvent` latency from ~2 µs to ~35 µs on Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*व्यावहारिक नोट्स*

- You can hit the length limit using any named kernel object (events, sections, semaphores…).
- Symbolic links or reparse points can point a short “victim” name to this giant component so the slowdown is applied transparently.
- Because everything lives in user-writable namespaces, the payload works from a standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

एक अधिक आक्रामक variant हजारों डायरेक्टरीज़ की एक श्रृंखला allocate करता है (`\BaseNamedObjects\A\A\...\X`). प्रत्येक hop directory resolution logic (ACL checks, hash lookups, reference counting) को trigger करता है, इसलिए प्रति-स्तर latency एक single string compare की तुलना में अधिक होती है। With ~16 000 levels (limited by the same `UNICODE_STRING` size), empirical timings लंबे single components द्वारा प्राप्त 35 µs barrier को पार कर जाती हैं।
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

* यदि parent directory डुप्लिकेट स्वीकार करना बंद कर दे तो प्रत्येक स्तर पर character बदलते रहें (`A/B/C/...`)।
* एक handle array रखें ताकि आप exploitation के बाद chain को साफ़-सुथरे तरीके से हटा सकें और namespace को प्रदूषित होने से बचा सकें।

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (माइक्रोसेकंड के बजाय मिनट)

Object directories **shadow directories** (fallback lookups) और entries के लिए bucketed hash tables का समर्थन करते हैं। इन दोनों का दुरुपयोग करें और 64-component symbolic-link reparse limit का उपयोग करके slowdown को गुणा करें बिना `UNICODE_STRING` लंबाई से अधिक हुए:

1. `\BaseNamedObjects` के अंतर्गत दो डायरेक्टरी बनाएं, जैसे `A` (shadow) और `A\A` (target)। दूसरी डायरेक्टरी को पहली को shadow directory के रूप में उपयोग करके बनाएं (`NtCreateDirectoryObjectEx`), ताकि `A` में missing lookups `A\A` पर फॉल-थ्रू हो जाएं।
2. प्रत्येक डायरेक्टरी को हज़ारों **colliding names** से भरें जो एक ही hash bucket में पड़ते हैं (उदा., trailing digits बदलते हुए लेकिन वही `RtlHashUnicodeString` value रखकर)। अब lookups एकल डायरेक्टरी के अंदर O(n) linear scans में degrade हो जाते हैं।
3. लगभग 63 की एक chain बनाएं जिसमें **object manager symbolic links** बार-बार लंबे `A\A\…` suffix में reparse करते हैं, जिससे reparse budget खर्च हो जाता है। हर reparse parsing को ऊपर से फिर से शुरू कर देता है, जिससे collision लागत गुणा हो जाती है।
4. final component (`...\\0`) का lookup अब Windows 11 पर प्रत्येक डायरेक्टरी में 16 000 collisions होने पर **minutes** लेता है, जो one-shot kernel LPEs के लिए व्यावहारिक रूप से सुनिश्चित race जीत प्रदान करता है।
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*क्यों यह महत्वपूर्ण है*: कुछ मिनटों की धीमी प्रतिक्रिया one-shot race-based LPEs को deterministic exploits में बदल देती है।

## अपने race window को मापना

अपने exploit के अंदर एक छोटा harness एम्बेड करें ताकि यह मापा जा सके कि victim hardware पर विंडो कितनी बड़ी हो जाती है। नीचे दिया गया snippet target object को `iterations` बार खोलता है और `QueryPerformanceCounter` का उपयोग करके प्रति-ओपन औसत लागत लौटाता है।
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

## शोषण कार्यप्रवाह

1. **Locate the vulnerable open** – kernel path को ट्रेस करें (symbols, ETW, hypervisor tracing, या reversing के माध्यम से) जब तक कि आपको कोई `NtOpen*`/`ObOpenObjectByName` कॉल न मिल जाए जो attacker-controlled name या user-writable directory में किसी symbolic link को वॉक करता हो।
2. **Replace that name with a slow path**
- `\BaseNamedObjects` (या किसी अन्य writable OM root) के अंतर्गत लंबा component या directory chain बनाइए।
- एक symbolic link बनाइए ताकि वो नाम जिसे kernel उम्मीद करता है अब slow path पर resolve हो। आप vulnerable driver के directory lookup को बिना original target को छुए अपनी structure की ओर निर्देशित कर सकते हैं।
3. **Trigger the race**
- Thread A (victim) vulnerable code को execute करता है और slow lookup के अंदर block हो जाता है।
- Thread B (attacker) guarded state को flip करता है (उदा., file handle बदलना, symbolic link को फिर से लिखना, object security toggle करना) जबकि Thread A व्यस्त है।
- जब Thread A resume होता है और privileged action करता है, तो वह stale state देखता है और attacker-controlled operation को निष्पादित कर देता है।
4. **Clean up** – directory chain और symbolic links को हटाकर संदिग्ध artifacts छोड़ने या legitimate IPC उपयोगकर्ताओं को तोड़ने से बचें।

## ऑपरेशनल विचार

- **Combine primitives** – आप directory chain में प्रति स्तर एक लंबा नाम उपयोग कर सकते हैं ताकि latency और बढ़े, जब तक कि आप `UNICODE_STRING` size को exhaust न कर दें।
- **One-shot bugs** – बढ़ा हुआ विंडो (दसियों माइक्रोसेकंड से मिनटों तक) “single trigger” bugs को realistic बनाता है जब इन्हें CPU affinity pinning या hypervisor-assisted preemption के साथ जोड़ा जाए।
- **Side effects** – slowdown केवल malicious path को प्रभावित करता है, इसलिए समग्र system performance प्रभावित नहीं होती; defenders शायद ही ध्यान देंगे जब तक कि वे namespace growth को मॉनिटर न कर रहे हों।
- **Cleanup** – आपने जो भी directory/object बनाया है उनके handles रखिए ताकि बाद में आप `NtMakeTemporaryObject`/`NtClose` कॉल कर सकें। वरना unbounded directory chains reboots के बाद भी बनी रह सकती हैं।

## रक्षा संबंधी नोट्स

- नामित objects पर निर्भर kernel code को open के *बाद* security-sensitive state को फिर से validate करना चाहिए, या check से पहले reference लेना चाहिए (TOCTOU gap को बंद करना)।
- user-controlled names को dereference करने से पहले OM path depth/length पर upper bounds लागू करें। अत्यधिक लंबे नामों को reject करने से attackers को फिर से microsecond विंडो में ही काम करना पड़ेगा।
- object manager namespace growth को instrument करें (ETW `Microsoft-Windows-Kernel-Object`) ताकि `\BaseNamedObjects` के नीचे suspicious हजारों-components chains का पता चल सके।

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
