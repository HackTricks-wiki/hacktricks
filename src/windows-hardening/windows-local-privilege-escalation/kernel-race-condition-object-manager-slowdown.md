# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Kwa nini kupanua dirisha la race ni muhimu

Mengi ya Windows kernel LPEs hufuata muundo wa kawaida `check_state(); NtOpenX("name"); privileged_action();`. Kwenye vifaa vya kisasa, `NtOpenEvent`/`NtOpenSection` baridi hutatua jina fupi kwa ~2 µs, ikiacha karibu hakuna muda wa kubadilisha hali iliyokaguliwa kabla ya kitendo salama kitokee. Kwa kusababisha kwa makusudi lookup ya Object Manager Namespace (OMNS) katika hatua ya 2 ichukue mfululizo wa mikrosekunde (µs), mshambuliaji anapata muda wa kutosha kushinda mara kwa mara races ambazo vinginevyo zingekuwa za mtego bila kuhitaji majaribio mengi.

## Muhtasari wa ndani ya utatuzi wa Object Manager

* **OMNS structure** – Majina kama `\BaseNamedObjects\Foo` hutatuliwa saraka kwa saraka. Kila sehemu husababisha kernel kutafuta/ufungue *Object Directory* na kulinganisha Unicode strings. Symbolic links (mfano, herufi za drive) zinaweza kupitiwa njiani.
* **UNICODE_STRING limit** – OM paths zinabebwa ndani ya `UNICODE_STRING` ambayo `Length` ni thamani ya 16-bit. Kiwango cha juu kabisa ni 65 535 bytes (32 767 UTF-16 codepoints). Kwa prefiksi kama `\BaseNamedObjects\`, mshambuliaji bado anadhibiti takriban ≈32 000 characters.
* **Attacker prerequisites** – Mtumiaji yeyote anaweza kuunda objects chini ya saraka zinazoweza kuandikwa kama `\BaseNamedObjects`. Wakati code iliyo dhaifu inatumia jina ndani yake, au inafuata symbolic link inayofika huko, mshambuliaji anadhibiti utendaji wa utatuzi bila ruhusa maalum.

## Slowdown primitive #1 – Single maximal component

Gharama ya kutatua sehemu ni takriban sawia na urefu wake kwa sababu kernel lazima ifanye kulinganisha Unicode dhidi ya kila kipengee kwenye saraka ya mzazi. Kuunda event yenye jina la 32 kB mara moja huwaongeza latency ya `NtOpenEvent` kutoka ~2 µs hadi ~35 µs kwenye Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Vidokezo vya vitendo*

- Unaweza kufikia kikomo cha urefu kwa kutumia aina yoyote ya named kernel object (events, sections, semaphores…).
- Symbolic links or reparse points zinaweza kuelekeza jina fupi la “victim” kwenye komponenti hii kubwa, ili slowdown itumike kwa uwazi.
- Kwa sababu kila kitu kiko katika user-writable namespaces, payload hufanya kazi kutoka standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Toleo kali zaidi huunda mnyororo wa maelfu ya directories (`\BaseNamedObjects\A\A\...\X`). Kila hop huanzisha directory resolution logic (ACL checks, hash lookups, reference counting), hivyo latency kwa kila ngazi ni kubwa kuliko single string compare. Kwa takriban ~16 000 ngazi (zinazotengwa na ukubwa uleule wa `UNICODE_STRING`), vipimo vya kimajaribio vinazidi kizuizi cha 35 µs kilichopatikana kwa long single components.
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

* Badilisha character kwa kila ngazi (`A/B/C/...`) ikiwa parent directory inaanza kukataa duplicates.
* Hifadhi handle array ili uweze kufuta mnyororo kwa usafi baada ya exploitation ili kuepuka kuchafua namespace.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (dakika badala ya microseconds)

Object directories support **shadow directories** (fallback lookups) and bucketed hash tables for entries. Abuse both plus the 64-component symbolic-link reparse limit to multiply slowdown without exceeding the `UNICODE_STRING` length:

1. Create two directories under `\BaseNamedObjects`, e.g. `A` (shadow) and `A\A` (target). Create the second using the first as the shadow directory (`NtCreateDirectoryObjectEx`), so missing lookups in `A` fall through to `A\A`.
2. Fill each directory with thousands of **colliding names** that land in the same hash bucket (e.g., varying trailing digits while keeping the same `RtlHashUnicodeString` value). Lookups now degrade to O(n) linear scans inside a single directory.
3. Build a chain of ~63 **object manager symbolic links** that repeatedly reparse into the long `A\A\…` suffix, consuming the reparse budget. Each reparse restarts parsing from the top, multiplying the collision cost.
4. Lookup of the final component (`...\\0`) now takes **dakika** on Windows 11 when 16 000 collisions are present per directory, providing a practically guaranteed race win for one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Kwa nini ni muhimu*: Kupungua kwa utendaji kwa muda wa dakika kunaweza kugeuza one-shot race-based LPEs kuwa deterministic exploits.

## Kupima dirisha la race

Weka chombo cha haraka ndani ya exploit yako ili kupima jinsi dirisha linavyopata kuwa kubwa kwenye kifaa cha mhusika. Kifupi hapa chini hufungua kitu lengwa `iterations` mara na kurudisha wastani wa gharama kwa kila ufunguzi kwa kutumia `QueryPerformanceCounter`.
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

1. **Locate the vulnerable open** – Fuata kernel path (kwa kutumia symbols, ETW, hypervisor tracing, au reversing) hadi upate wito `NtOpen*`/`ObOpenObjectByName` unaotembeza attacker-controlled name au symbolic link katika user-writable directory.
2. **Replace that name with a slow path**
- Tengeneza long component au directory chain chini ya `\BaseNamedObjects` (au OM root nyingine inayoweza kuandikwa).
- Tengeneza symbolic link ili jina ambalo kernel linatarajia sasa liwe resolving kwa slow path. Unaweza kuielekeza vulnerable driver’s directory lookup kwenye structure yako bila kugusa target asilia.
3. **Trigger the race**
- Thread A (victim) inafanya vulnerable code na inakaa ndani ya slow lookup.
- Thread B (attacker) inabadilisha guarded state (mfano, swaps a file handle, rewrites a symbolic link, toggles object security) wakati Thread A yuko occupied.
- Wakati Thread A inarudisha kazi na inafanya privileged action, inaona stale state na inafanya attacker-controlled operation.
4. **Clean up** – Futa directory chain na symbolic links ili kuepuka kuacha artifacts zenye kutiliwa shaka au kuvunja watumiaji halali wa IPC.

## Operational considerations

- **Combine primitives** – Unaweza kutumia long name *per level* katika directory chain kwa latency zaidi hadi utumie kabisa ukubwa wa `UNICODE_STRING`.
- **One-shot bugs** – Dirisha lililopanuka (tens of microseconds hadi minutes) linafanya “single trigger” bugs kuwa halisi wakati limehusishwa na CPU affinity pinning au hypervisor-assisted preemption.
- **Side effects** – Slowdown inaathiri tu malicious path, hivyo utendaji mzima wa mfumo hautaathirika; defenders wataona nadra isipokuwa wakifuatilia ukuaji wa namespace.
- **Cleanup** – Weka handles kwa kila directory/object unayounda ili uweze kuita `NtMakeTemporaryObject`/`NtClose` baadaye. Unbounded directory chains zinaweza kudumu hata baada ya reboot.

## Defensive notes

- Kernel code inayotegemea named objects inapaswa kure-validate security-sensitive state *baada ya* open, au ichukue reference kabla ya check (kufunga TOCTOU gap).
- Weka vizingiti vya juu juu ya OM path depth/length kabla ya dereferencing user-controlled names. Kukataa majina marefu kupforce attackers kurudi kwenye microsecond window.
- Instrument object manager namespace growth (ETW `Microsoft-Windows-Kernel-Object`) ili kubaini mnyororo zenye maelfu ya components zenye kutiliwa shaka chini ya `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
