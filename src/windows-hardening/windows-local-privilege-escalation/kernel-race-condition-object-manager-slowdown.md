# Utekelezaji wa Kernel Race Condition kupitia Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Kwa nini kuongeza dirisha la race ni muhimu

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. On modern hardware a cold `NtOpenEvent`/`NtOpenSection` resolves a short name in ~2 µs, leaving almost no time to flip the checked state before the secure action happens. By deliberately forcing the Object Manager Namespace (OMNS) lookup in step 2 to take tens of microseconds, the attacker gains enough time to consistently win otherwise flaky races without needing thousands of attempts.

## Ndani ya utendaji wa Object Manager lookup kwa muhtasari

* **OMNS structure** – Names such as `\BaseNamedObjects\Foo` are resolved directory-by-directory. Each component causes the kernel to find/open an *Object Directory* and compare Unicode strings. Symbolic links (e.g., drive letters) may be traversed en route.
* **UNICODE_STRING limit** – OM paths are carried inside a `UNICODE_STRING` whose `Length` is a 16-bit value. The absolute limit is 65 535 bytes (32 767 UTF-16 codepoints). With prefixes like `\BaseNamedObjects\`, an attacker still controls ≈32 000 characters.
* **Attacker prerequisites** – Any user can create objects underneath writable directories such as `\BaseNamedObjects`. When the vulnerable code uses a name inside, or follows a symbolic link that lands there, the attacker controls the lookup performance with no special privileges.

## Primitive ya kupunguza kasi #1 – Single maximal component

The cost of resolving a component is roughly linear with its length because the kernel must perform a Unicode comparison against every entry in the parent directory. Creating an event with a 32 kB-long name immediately increases the `NtOpenEvent` latency from ~2 µs to ~35 µs on Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Vidokezo vya vitendo*

- Unaweza kufikia kikomo cha urefu ukitumia named kernel object yoyote (events, sections, semaphores…).
- Symbolic links au reparse points zinaweza kuelekeza jina fupi la “mhusika” kwa kipengele hiki kikubwa ili slowdown itumike kwa uwazi.
- Kwa kuwa kila kitu kipo katika namespaces zinazoweza kuandikwa na mtumiaji, payload hufanya kazi kutoka kwenye standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Toleo kali zaidi hutoa mnyororo wa maelfu ya direktori (`\BaseNamedObjects\A\A\...\X`). Kila hatua huamsha mantiki ya utatuzi wa directory (ACL checks, hash lookups, reference counting), hivyo latency kwa kila ngazi ni kubwa zaidi kuliko single string compare. Kwa takriban ~16 000 ngazi (ilimitiwa na ukubwa ule ule wa `UNICODE_STRING`), mipimo ya kimajaribio inavuka kizuizi cha 35 µs kilichopatikana na long single components.
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

* Badilisha tabia kwa kila ngazi (`A/B/C/...`) ikiwa saraka mzazi itaanza kukataa duplicates.
* Weka handle array ili uweze kufuta mnyororo kwa usafi baada ya exploitation ili kuepuka kuchafua namespace.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (dakika badala ya mikrosekunde)

Object directories zinaunga mkono **shadow directories** (fallback lookups) na bucketed hash tables kwa entries. Chukiza zote mbili pamoja na kikomo cha 64-component symbolic-link reparse ili kuzidisha ucheleweshaji bila kuzidi urefu wa `UNICODE_STRING`:

1. Unda saraka mbili chini ya `\BaseNamedObjects`, kwa mfano `A` (shadow) na `A\A` (target). Unda ya pili ukitumia ya kwanza kama shadow directory (`NtCreateDirectoryObjectEx`), ili tafutio zisizopatikana katika `A` zitapita hadi `A\A`.
2. Jaza kila saraka na maelfu ya **colliding names** ambazo zinaingia katika hash bucket ile ile (mfano, kubadilisha tarakimu za mwisho huku ukihifadhi thamani ile ile ya `RtlHashUnicodeString`). Tafutio sasa zinashuka hadi skana za mstari O(n) ndani ya saraka moja.
3. Jenga mnyororo wa takriban ~63 wa **object manager symbolic links** ambao mara kwa mara hu-reparse ndani ya kifupi kirefu `A\A\…`, wakitumia reparse budget. Kila reparse huanzisha tena parsing kutoka juu, zikizidisha gharama ya collision.
4. Tafutio ya sehemu ya mwisho (`...\\0`) sasa huchukua **dakika** kwenye Windows 11 wakati 16 000 collisions zipo kwa kila saraka, ikitoa ushindi wa race unaokaribia hakika kwa one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Kwanini ni muhimu*: Kuporomoka kwa muda wa dakika kadhaa kunageuza one-shot race-based LPEs kuwa deterministic exploits.

## Kupima dirisha la race

Ingiza harness fupi ndani ya exploit yako ili kupima jinsi dirisha linavyokuwa kubwa kwenye kifaa cha mwathiriwa. Mfano hapa chini hufungua target object `iterations` mara na kurudisha wastani wa gharama kwa kila ufunguzi ukitumia `QueryPerformanceCounter`.
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
Matokeo yanaingia moja kwa moja kwenye mkakati wako wa uendeshaji wa race (kwa mfano, idadi ya worker threads zinazohitajika, interval za usingizi, ni mapema kiasi gani unahitaji kubadili shared state).

## Mtiririko wa matumizi ya udhaifu

1. **Tafuta open iliyo na udhaifu** – Fuata njia ya kernel (kwa kupitia symbols, ETW, hypervisor tracing, au reversing) hadi utakapopata wito wa `NtOpen*`/`ObOpenObjectByName` unaotembeza jina linalodhibitiwa na mshambuliaji au symbolic link katika directory inayoweza kuandikwa na mtumiaji.
2. **Badilisha jina hilo na slow path**
- Tengeneza component ndefu au mnyororo wa directory chini ya `\BaseNamedObjects` (au OM root nyingine inayoweza kuandikwa).
- Tengeneza symbolic link ili jina linalotarajiwa na kernel sasa litamwonyesha slow path. Unaweza kuelekeza directory lookup ya driver yenye udhaifu kwenye muundo wako bila kugusa lengo la awali.
3. **Sawazisha race**
- Thread A (mwendeshaji) inatekeleza code yenye udhaifu na inakaa (blocks) ndani ya lookup polepole.
- Thread B (mshambuliaji) inabadilisha guarded state (kwa mfano, kubadilisha file handle, kuandika upya symbolic link, kubadili object security) wakati Thread A iko occupied.
- Wakati Thread A inaporudi na kufanya hatua yenye ruhusa, inaona stale state na inafanya operesheni ndogo-dhibitiwa na mshambuliaji.
4. **Safisha** – Futa mnyororo wa directory na symbolic links ili kuepuka kuacha artifacts zenye shaka au kuvunja watumiaji halali wa IPC.

## Mambo ya uendeshaji

- **Combine primitives** – Unaweza kutumia jina ndefu kwa kila kiwango katika mnyororo wa directory kwa latency kubwa zaidi hadi utakapochoka `UNICODE_STRING` size.
- **One-shot bugs** – Dirisha lililopanuka (mikoa ya microseconds kumi hadi dakika) linafanya “single trigger” bugs kuwa halisi wakati likiambatana na CPU affinity pinning au hypervisor-assisted preemption.
- **Madhara ya pembeni** – Kupungua kwa kasi kunahusu njia mbaya tu, hivyo utendaji wa jumla wa mfumo hauathiriwi; watetezi mara chache wataona isipokuwa wakiwawanasa ukuaji wa namespace.
- **Usafishaji** – Hifadhi handles za kila directory/object unazozitengeneza ili uweze kuita `NtMakeTemporaryObject`/`NtClose` baadaye. Mnyororo usio na mipaka unaweza kudumu hata baada ya reboot.

## Vidokezo vya ulinzi

- Kernel code inayotegemea named objects inapaswa kuthibitisha tena state zinazohusiana na usalama *baada ya* open, au ichukue reference kabla ya ukaguzi (kufunga doa la TOCTOU).
- Weka mipaka ya juu kwa kina/urefu wa OM path kabla ya kufanya dereference kwa majina yanayodhibitiwa na mtumiaji. Kukataa majina marefu sana kunasukuma mashambulizi kurudi kwenye dirisha la microsecond.
- Pima ukuaji wa namespace ya object manager (ETW `Microsoft-Windows-Kernel-Object`) ili kugundua mnyororo wa maelfu ya components yenye shaka chini ya `\BaseNamedObjects`.

## Marejeleo

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
