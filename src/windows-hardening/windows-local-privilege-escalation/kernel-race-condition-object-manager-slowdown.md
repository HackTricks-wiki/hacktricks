# Exploitation ya Kernel Race Condition kupitia Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Kwa nini kuongeza race window ni muhimu

LPE nyingi za Windows kernel hufuata muundo wa kawaida `check_state(); NtOpenX("name"); privileged_action();`. Kwenye hardware ya kisasa, `NtOpenEvent`/`NtOpenSection` isiyo kwenye cache hutatua jina fupi kwa takriban ~2 µs, hivyo kubaki na muda mdogo sana wa kubadilisha hali iliyokaguliwa kabla ya secure action kutokea. Kwa kulazimisha lookup ya Object Manager Namespace (OMNS) katika hatua ya 2 ichukue makumi ya microseconds, attacker hupata muda wa kutosha kushinda kwa uthabiti race ambazo vinginevyo zingekuwa flaky bila kuhitaji majaribio ya maelfu.<sup>[[1]](#references)</sup>

## Object Manager lookup internals kwa ufupi

* **Muundo wa OMNS** – Majina kama `\BaseNamedObjects\Foo` hutatuliwa directory baada ya directory. Kila component husababisha kernel kutafuta/kufungua *Object Directory* na kulinganisha Unicode strings. Symbolic links (kwa mfano, drive letters) zinaweza kufuatwa njiani.
* **Kikomo cha UNICODE_STRING** – OM paths hubebwa ndani ya `UNICODE_STRING` ambayo `Length` yake ni thamani ya 16-bit. Kikomo kamili ni bytes 65 535 (UTF-16 codepoints 32 767). Kwa prefixes kama `\BaseNamedObjects\`, attacker bado ana udhibiti wa takriban ≈32 000 characters.
* **Masharti ya attacker** – User yoyote anaweza kuunda objects ndani ya directories zinazoandikika kama `\BaseNamedObjects`. Wakati vulnerable code inapotumia jina lililo ndani yake, au inapofuata symbolic link inayoishia hapo, attacker hudhibiti performance ya lookup bila special privileges.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Single maximal component

Gharama ya kutatua component huwa takriban linear kulingana na urefu wake kwa sababu kernel lazima ifanye Unicode comparison dhidi ya kila entry iliyo katika parent directory. Kuunda event yenye jina lenye urefu wa 32 kB huongeza mara moja latency ya `NtOpenEvent` kutoka ~2 µs hadi ~35 µs kwenye Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Maelezo ya vitendo*

- Unaweza kufikia kikomo cha urefu kwa kutumia kernel object yoyote yenye jina (events, sections, semaphores…).
- Symbolic links au reparse points zinaweza kuelekeza jina fupi la “victim” kwenye component hii kubwa, hivyo slowdown hutekelezwa kwa uwazi.
- Kwa kuwa kila kitu kiko katika namespaces zinazoweza kuandikwa na user, payload hufanya kazi kutoka kiwango cha kawaida cha user integrity.<sup>[[1]](#references)</sup>

## Primitive ya slowdown #2 – Directories recursive za kina

Toleo lenye ukali zaidi hutenga mnyororo wa maelfu ya directories (`\BaseNamedObjects\A\A\...\X`). Kila hop huanzisha directory resolution logic (ACL checks, hash lookups, reference counting), hivyo latency ya kila level huwa kubwa kuliko kulinganisha string moja. Kwa takriban levels 16,000 (zinazowekewa kikomo na ukubwa huohuo wa `UNICODE_STRING`), vipimo vya majaribio huzidi kizingiti cha 35 µs kilichofikiwa na components ndefu za pekee.
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
* Hifadhi handle array ili uweze kufuta chain vizuri baada ya exploitation na kuepuka kuchafua namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (dakika badala ya microseconds)

Object directories zinaunga mkono **shadow directories** (fallback lookups) na hash tables zenye buckets kwa entries. Tumia vibaya vyote viwili pamoja na kikomo cha 64-component symbolic-link reparse ili kuongeza slowdown bila kuzidi urefu wa `UNICODE_STRING`:

1. Unda directories mbili chini ya `\BaseNamedObjects`, kwa mfano `A` (shadow) na `A\A` (target). Unda ya pili ukitumia ya kwanza kama shadow directory (`NtCreateDirectoryObjectEx`), ili lookups zinazokosa katika `A` ziendelee kwenye `A\A`.
2. Jaza kila directory kwa maelfu ya **colliding names** zinazoingia kwenye hash bucket moja (kwa mfano, badilisha trailing digits huku ukihifadhi thamani ileile ya `RtlHashUnicodeString`). Lookups sasa hupungua hadi O(n) linear scans ndani ya directory moja.
3. Jenga chain ya takribani **object manager symbolic links** 63 ambazo mara kwa mara hufanya reparse kuelekea suffix ndefu ya `A\A\…`, na kutumia reparse budget. Kila reparse huanzisha tena parsing kutoka juu, na hivyo kuzidisha collision cost.
4. Lookup ya final component (`...\\0`) sasa huchukua **dakika** kwenye Windows 11 wakati collisions 16 000 zipo kwa kila directory, na kutoa ushindi wa race unaokaribia kuhakikishwa kwa kernel LPEs za one-shot.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Kwa nini ni muhimu*: Slowdown ya dakika kadhaa hubadilisha LPEs za race za jaribio moja kuwa exploits zinazotabirika.<sup>[[1]](#references)</sup>

### Maelezo ya retest ya 2025 na tooling iliyotengenezwa tayari

- James Forshaw alichapisha tena technique hii akiwa na timings zilizosasishwa kwenye Windows 11 24H2 (ARM64). Ufunguaji wa msingi bado ni takriban ~2 µs; component ya 32 kB huongeza muda huu hadi ~35 µs, na shadow-dir + collision + chains za 63-reparse bado hufikia ~dakika 3, jambo linalothibitisha kuwa primitives bado zinafanya kazi kwenye builds za sasa. Source code na perf harness zinapatikana kwenye Project Zero post iliyosasishwa.<sup>[[1]](#references)</sup>
- Unaweza kuscript setup kwa kutumia bundle ya public `symboliclink-testing-tools`: `CreateObjectDirectory.exe` kuunda shadow/target pair na `NativeSymlink.exe` kwenye loop ili kutoa chain ya 63-hop. Hii huepuka kuandika mwenyewe wrappers za `NtCreate*` na huhakikisha ACLs zinabaki thabiti.<sup>[[2]](#references)</sup>

## Kupima race window yako

Embed harness fupi ndani ya exploit yako ili kupima ukubwa wa window kwenye hardware ya victim. Snippet iliyo hapa chini hufungua target object mara `iterations` na kurudisha wastani wa gharama ya kila ufunguaji kwa kutumia `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Matokeo yanaingia moja kwa moja kwenye mkakati wako wa orchestration ya race (kwa mfano, idadi ya worker threads zinazohitajika, vipindi vya sleep, na muda wa kugeuza shared state).

## Mtiririko wa exploitation

1. **Tambua open iliyo vulnerable** – Fuatilia kernel path (kupitia symbols, ETW, hypervisor tracing, au reversing) hadi upate call ya `NtOpen*`/`ObOpenObjectByName` inayopitia jina linalodhibitiwa na attacker au symbolic link iliyo kwenye user-writable directory.
2. **Badilisha jina hilo liende kwenye slow path**
- Unda long component au directory chain chini ya `\BaseNamedObjects` (au OM root nyingine inayoweza kuandikwa).
- Unda symbolic link ili jina linalotarajiwa na kernel sasa lielekee kwenye slow path. Unaweza kuelekeza directory lookup ya vulnerable driver kwenye muundo wako bila kugusa target ya awali.
3. **Trigger race**
- Thread A (victim) hutekeleza vulnerable code na kublokika ndani ya slow lookup.
- Thread B (attacker) hubadilisha guarded state (kwa mfano, kubadilisha file handle, kuandika upya symbolic link, au kubadilisha object security) wakati Thread A iko busy.
- Thread A inaporesume na kufanya privileged action, huona state iliyopitwa na wakati na kutekeleza attacker-controlled operation.
4. **Fanya cleanup** – Futa directory chain na symbolic links ili kuepuka kuacha suspicious artifacts au kuvuruga legitimate IPC users.<sup>[[1]](#references)</sup>

## Mambo ya kuzingatia kiutendaji

- **Unganisha primitives** – Unaweza kutumia long name *kwa kila level* katika directory chain ili kupata latency kubwa zaidi hadi umalize `UNICODE_STRING` size.
- **One-shot bugs** – Window iliyopanuliwa (makumi ya microseconds hadi dakika) hufanya “single trigger” bugs ziwe realistic zinapounganishwa na CPU affinity pinning au hypervisor-assisted preemption.
- **Side effects** – Slowdown huathiri tu malicious path, hivyo system performance kwa ujumla hubaki bila kuathiriwa; defenders hawataona kwa urahisi isipokuwa wafuatilie namespace growth.
- **Cleanup** – Hifadhi handles za kila directory/object unayounda ili uweze kuita `NtMakeTemporaryObject`/`NtClose` baadaye. Directory chains zisizo na kikomo zinaweza kubaki baada ya reboots vinginevyo.
- **File-system races** – Ikiwa vulnerable path hatimaye inapitia NTFS, unaweza kuweka Oplock (kwa mfano, `SetOpLock.exe` kutoka kwenye toolkit hiyo hiyo) kwenye backing file wakati OM slowdown ikiendelea, na kumfanya consumer asimame kwa milliseconds zaidi bila kubadilisha OM graph.<sup>[[2]](#references)</sup>

## Maelezo ya kujilinda

- Kernel code inayotegemea named objects inapaswa ku-validate tena security-sensitive state *baada* ya open, au ichukue reference kabla ya check (kufunga TOCTOU gap).
- Weka upper bounds kwenye OM path depth/length kabla ya kudereference user-controlled names. Kukataa majina marefu kupita kiasi huwalazimisha attackers kurudi kwenye microsecond window.
- Instrument object manager namespace growth (ETW `Microsoft-Windows-Kernel-Object`) ili kugundua suspicious chains zenye maelfu ya components chini ya `\BaseNamedObjects`.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
