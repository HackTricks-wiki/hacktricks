# Kuitumia Kernel Race Condition kupitia Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Kwanini kupanua dirisha la race kuna umuhimu

Windows kernel LPEs nyingi zifuata mfano wa kawaida `check_state(); NtOpenX("name"); privileged_action();`. Kwa vifaa vya kisasa, simu ya kwanza (cold) ya `NtOpenEvent`/`NtOpenSection` inatatua jina fupi kwa ~2 µs, ikiacha karibu hakuna muda wa kubadilisha hali iliyokaguliwa kabla ya kitendo cha usalama kutokea. Kwa kulazimisha kwa makusudi lookup ya Object Manager Namespace (OMNS) katika hatua ya 2 ichukue miongo ya mikrosekunde, mshambuliaji anapata muda wa kutosha kushinda kwa uthabiti races ambazo vinginevyo zingekuwa za kutokuwa na uhakika bila kuhitaji maelfu ya jaribio.

## Object Manager lookup internals kwa kifupi

* **OMNS structure** – Majina kama `\BaseNamedObjects\Foo` yanatatuliwa directory-by-directory. Kila sehemu husababisha kernel kutafuta/kufungua *Object Directory* na kulinganisha Unicode strings. Symbolic links (mfano, herufi za drive) zinaweza kupitiwa njiani.
* **UNICODE_STRING limit** – OM paths zinabebwa ndani ya `UNICODE_STRING` ambao `Length` ni thamani ya 16-bit. Kiwango kamili ni 65 535 bytes (32 767 UTF-16 codepoints). Kwa prefiksi kama `\BaseNamedObjects\`, mshambuliaji bado anadhibiti takriban ≈32 000 characters.
* **Attacker prerequisites** – Mtumiaji yeyote anaweza kuunda objects chini ya directories zinazoweza kuandikwa kama `\BaseNamedObjects`. Wakati code dhaifu inatumia jina ndani yake, au inafuata symbolic link inayomaliza huko, mshambuliaji anadhibiti utendaji wa lookup bila ruhusa maalum.

## Slowdown primitive #1 – Single maximal component

Gharama ya kutatua sehemu ni takriban proportional na urefu wake kwa sababu kernel lazima ifanye comparison ya Unicode dhidi ya kila entry kwenye parent directory. Kuunda event iliyo na jina la urefu wa 32 kB mara moja kunaongeza latency ya `NtOpenEvent` kutoka ~2 µs hadi ~35 µs kwenye Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Vidokezo vya vitendo*

- Unaweza kufikia kikomo cha urefu ukitumia chochote named kernel object (events, sections, semaphores…).
- Symbolic links au reparse points zinaweza kuonyesha short “victim” name kwa this giant component ili slowdown itumike kwa uwazi.
- Kwa sababu kila kitu kiko katika user-writable namespaces, the payload inafanya kazi kutoka kwa standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

A more aggressive variant huallocate mnyororo wa maelfu ya directories (`\BaseNamedObjects\A\A\...\X`). Kila hop husababisha directory resolution logic (ACL checks, hash lookups, reference counting), hivyo latency kwa kila ngazi iko juu kuliko single string compare. Kwa ~16 000 levels (imezuiliwa na `UNICODE_STRING` size), empirical timings zinazidi kizuizi cha 35 µs kilichopatikana na long single components.
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

* Badilisha herufi kwa kila ngazi (`A/B/C/...`) ikiwa saraka ya mzazi inaanza kukataa nakala.
* Keep a handle array ili uweze kufuta mnyororo kwa usafi baada ya exploitation ili kuepuka kuchafuza namespace.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (dakika badala ya microseconds)

Object directories zinaunga mkono **shadow directories** (fallback lookups) na bucketed hash tables kwa entries. Tumia zote mbili pamoja na 64-component symbolic-link reparse limit kuongeza slowdown bila kuzidi `UNICODE_STRING` length:

1. Tengeneza directories mbili chini ya `\BaseNamedObjects`, mfano `A` (shadow) na `A\A` (target). Tengeneza ya pili ukitumia ya kwanza kama shadow directory (`NtCreateDirectoryObjectEx`), ili lookup zinazokosekana katika `A` zipite kwa `A\A`.
2. Jaza kila directory kwa maelfu ya **colliding names** ambazo zinaingia kwenye hash bucket moja (mfano, kubadilisha tarakimu za nyuma huku ukihifadhi thamani ile ile ya `RtlHashUnicodeString`). Lookup sasa hubadilika kuwa skani ya mstari O(n) ndani ya directory moja.
3. Jenga mnyororo wa takriban ~63 wa **object manager symbolic links** ambao hupitwa tena na tena reparse ndani ya long `A\A\…` suffix, wakitumia reparse budget. Kila reparse huanza tena parsing kutoka juu, kuongeza gharama ya collision.
4. Lookup ya kipengele cha mwisho (`...\\0`) sasa huchukua **dakika** kwenye Windows 11 wakati kuna 16 000 collisions kwa directory, ikitoa ushindi wa race ulio karibu uhakika kwa one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Kwa nini ni muhimu*: Kupunguzwa kwa muda wa dakika hugeuza one-shot race-based LPEs kuwa deterministic exploits.

### Vidokezo vya upimaji tena 2025 & zana zilizotayarishwa

- James Forshaw alichapisha tena mbinu hiyo na timings zilizosasishwa kwenye Windows 11 24H2 (ARM64). Ufunguzi wa msingi unabaki ~2 µs; sehemu ya 32 kB inaongeza hadi ~35 µs, na shadow-dir + collision + 63-reparse chains bado zinaleta ~3 dakika, zikithibitisha primitives zinaendelea kufanya kazi kwenye builds za sasa. Source code na perf harness ziko katika chapisho la Project Zero lililosasishwa.
- Unaweza ku-script setup ukitumia public `symboliclink-testing-tools` bundle: `CreateObjectDirectory.exe` kuanzisha jozi ya shadow/target na `NativeSymlink.exe` katika loop kutolewa kwa 63-hop chain. Hii inazuia wrappers za `NtCreate*` zilizoandikwa kwa mkono na inahakikisha ACLs zinabaki thabiti.

## Kupima dirisha lako la race

Weka harness mfupi ndani ya exploit yako ili kupima ni kubwa kiasi gani dirisha linakuwa kwenye hardware ya victim. Snippet hapo chini hufungua target object `iterations` mara na kurudisha wastani wa gharama kwa kila ufunguzi kwa kutumia `QueryPerformanceCounter`.
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
Matokeo yanachangia moja kwa moja katika mkakati wako wa kuandaa race (mfano, idadi ya worker threads zinazohitajika, sleep intervals, ni mapema kiasi gani unahitaji kubadilisha shared state).

## Mtiririko wa Exploitation

1. **Locate the vulnerable open** – Fuata njia ya kernel (kwa kupitia symbols, ETW, hypervisor tracing, au reversing) hadi utakapokutana na wito wa `NtOpen*`/`ObOpenObjectByName` ambao unatembea jina linalodhibitiwa na mshambulizi au symbolic link katika directory ambayo mtumiaji anaweza kuandika.
2. **Replace that name with a slow path**
- Unda component ndefu au mnyororo wa directory chini ya `\BaseNamedObjects` (au OM root nyingine inayoweza kuandikwa).
- Unda symbolic link ili jina ambalo kernel linatarajia sasa litamalizika kwenye slow path. Unaweza kuelekeza utafutaji wa directory wa driver dhaifu kwa muundo wako bila kugusa target ya awali.
3. **Trigger the race**
- Thread A (victim) inaendesha code dhaifu na inakwama ndani ya lookup ya slow.
- Thread B (attacker) hubadilisha guarded state (mfano, kubadilisha file handle, kuandika upya symbolic link, kubadilisha object security) wakati Thread A iko occupied.
- Wakati Thread A inarudi na kutekeleza kitendo chenye vibali, inaona stale state na inafanya operesheni inayodhibitiwa na mshambulizi.
4. **Clean up** – Futa mnyororo wa directory na symbolic links ili kuepuka kuachia artifacts zenye mashaka au kuvunja watumiaji halali wa IPC.

## Mambo ya kiutendaji

- **Combine primitives** – Unaweza kutumia jina ndefu *kila ngazi* katika mnyororo wa directory kwa latency ya juu zaidi hadi utumie ukubwa wa `UNICODE_STRING`.
- **One-shot bugs** – Dirisha lililopanuka (malli ya microseconds hadi dakika) hufanya “single trigger” bugs kuwa za kimantiki wakati zinapangiliwa na CPU affinity pinning au hypervisor-assisted preemption.
- **Side effects** – Kupunguza kasi kunahusu tu path ya uharibifu, kwa hivyo utendaji wa jumla wa mfumo hauathiriki; watetezi mara chache wataona isipokuwa wakifuatilia ukuaji wa namespace.
- **Cleanup** – Weka handles kwa kila directory/object unayounda ili uweze kuita `NtMakeTemporaryObject`/`NtClose` baadaye. Mnyororo usio na mipaka wa directory unaweza kudumu baada ya reboot vinginevyo.
- **File-system races** – Ikiwa path dhaifu hatimaye inamalizika kupitia NTFS, unaweza kuweka Oplock (mfano, `SetOpLock.exe` kutoka kwenye toolkit hiyo hiyo) kwenye faili ya backing wakati OM slowdown inafanya kazi, ukizima consumer kwa millisecond za ziada bila kubadilisha OM graph.

## Vidokezo vya kujilinda

- Kernel code inayotegemea named objects inapaswa kuthibitisha upya hali nyeti za usalama *baada ya* open, au kuchukua reference kabla ya ukaguzi (kufunga pengo la TOCTOU).
- Tekeleza mipaka ya juu kwenye kina/urefu wa OM path kabla ya kudereference majina yanayodhibitiwa na mtumiaji. Kukataa majina marefu sana kunasukuma wasumizi kurudi katika dirisha la microsecond.
- Pima ukuaji wa namespace ya object manager (ETW `Microsoft-Windows-Kernel-Object`) ili kutambua mnyororo zenye maelfu ya components zenye mshaka chini ya `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
