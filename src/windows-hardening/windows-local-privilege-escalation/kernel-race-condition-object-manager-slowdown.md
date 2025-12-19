# Utekelezaji wa Kernel Race Condition kupitia Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Kwa nini kupanua dirisha la race ni muhimu

LPE nyingi za kernel za Windows zinafuata muundo wa kawaida `check_state(); NtOpenX("name"); privileged_action();`. Kwenye vifaa vya kisasa, `NtOpenEvent`/`NtOpenSection` baridi hutatua jina fupi kwa takriban ~2 µs, ikiacha karibu hakuna muda wa kubadilisha hali iliyohakikiwa kabla kitendo chenye usalama kifanyike. Kwa kulazimisha kwa makusudi Object Manager Namespace (OMNS) lookup kwenye hatua ya 2 ichukue mfululizo wa microsecond, mshambulizi hupata muda wa kutosha kushinda mara kwa mara mashindano ambayo vinginevyo yangekuwa tete bila haja ya majaribio elfu nyingi.

## Muundo wa ndani wa lookup ya Object Manager kwa ufupi

* **OMNS structure** – Majina kama `\BaseNamedObjects\Foo` hutatuliwa saraka kwa saraka. Kila sehemu husababisha kernel kutafuta/kuvuta *Object Directory* na kulinganisha Unicode strings. Symbolic links (mfano, herufi za drive) zinaweza kupitiwa njiani.
* **UNICODE_STRING limit** – Njia za OM zinabebwa ndani ya `UNICODE_STRING` ambayo `Length` ni thamani ya 16-bit. Kikomo kamili ni 65 535 bytes (32 767 UTF-16 codepoints). Kwa prefixes kama `\BaseNamedObjects\`, mshambulizi bado ana udhibiti wa takriban ≈32 000 tabia.
* **Attacker prerequisites** – Mtumiaji yeyote anaweza kuunda objects chini ya saraka zinazoweza kuandikwa kama `\BaseNamedObjects`. Wakati code ilio dhaifu inatumia jina ndani yake, au inafuata symbolic link inayomalizia huko, mshambulizi anadhibiti utendaji wa lookup bila ruhusa maalum.

## Slowdown primitive #1 – Single maximal component

Gharama ya kutatua sehemu ni takriban mstari kulingana na urefu wake kwa sababu kernel lazima ifanye ulinganisho wa Unicode dhidi ya kila kipengee katika parent directory. Kuunda event yenye jina la urefu 32 kB mara moja huongeza latency ya `NtOpenEvent` kutoka ~2 µs hadi ~35 µs kwenye Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Vidokezo vya vitendo*

- Unaweza kufikia kikomo cha urefu kwa kutumia any named kernel object (events, sections, semaphores…).
- Symbolic links au reparse points zinaweza kuelekeza jina fupi “victim” kwa giant component hii ili slowdown itumike kwa uwazi.
- Kwa kuwa kila kitu kiko katika user-writable namespaces, payload inafanya kazi kutoka standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Toleo kali zaidi huunda mnyororo wa maelfu ya directories (`\BaseNamedObjects\A\A\...\X`). Kila hatua huanzisha directory resolution logic (ACL checks, hash lookups, reference counting), hivyo latency kwa kila ngazi ni kubwa kuliko kulinganisha kamba moja. Kwa ~16 000 ngazi (iliyopunguzwa na ukubwa ule ule wa `UNICODE_STRING`), vipimo vya majaribio vinavuka kizuizi cha 35 µs kilichopatikana kwa long single components.
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

* Badilisha herufi kwa kila ngazi (`A/B/C/...`) ikiwa directory ya mzazi inaanza kukataa nakala zinazojirudia.
* Hifadhi handle array ili uweze kufuta chain kwa usafi baada ya exploitation ili kuepuka kuchafua namespace.

## Kupima race window

Ingiza harness fupi ndani ya exploit yako ili kupima ni kubwa gani dirisha linapokuwa kwenye hardware ya mhusika. Kipande hapa chini hufungua target object `iterations` mara na hurudisha wastani wa gharama kwa kila ufunguaji kwa kutumia `QueryPerformanceCounter`.
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
Matokeo huingizwa moja kwa moja kwenye mkakati wako wa race orchestration (kwa mfano, idadi ya worker threads zinazohitajika, kipindi cha usingizi, ni mapema kiasi gani unahitaji kubadili shared state).

## Exploitation workflow

1. **Locate the vulnerable open** – Fuata njia ya kernel (kwa kutumia symbols, ETW, hypervisor tracing, au reversing) hadi utakapopata wito wa `NtOpen*`/`ObOpenObjectByName` unaosonga jina linalodhibitiwa na mshambuliaji au symbolic link kwenye directory inayoweza kuandikwa na mtumiaji.
2. **Replace that name with a slow path**
- Unda component ndefu au mnyororo wa directories chini ya `\BaseNamedObjects` (au OM root nyingine inayoweza kuandikwa).
- Unda symbolic link ili jina ambalo kernel linatarajia sasa liwekeze kwenye slow path. Unaweza kuelekeza directory lookup ya driver dhaifu kwa muundo wako bila kugusa target ya asili.
3. **Trigger the race**
- Thread A (victim) inatekeleza code yenye udhaifu na inazuia ndani ya slow lookup.
- Thread B (attacker) hubadili guarded state (kwa mfano, kubadilisha file handle, kuandika upya symbolic link, kubadilisha object security) wakati Thread A iko occupied.
- Wakati Thread A inarejeshwa na inafanya kitendo kilicho na privileges, inaona stale state na inafanya operation inayodhibitiwa na mshambuliaji.
4. **Clean up** – Futa mnyororo wa directory na symbolic links ili kuepuka kuacha artifacts zinazoshukuwa au kuvunja watumiaji halali wa IPC.

## Operational considerations

- **Combine primitives** – Unaweza kutumia long name kwa *level* katika mnyororo wa directory kwa latency ya juu zaidi hadi utakapochosha `UNICODE_STRING` size.
- **One-shot bugs** – Dirisha lililopanuliwa (michache ya microseconds) linafanya bug za “single trigger” kuwa halisi wakati zinapochanganywa na CPU affinity pinning au hypervisor-assisted preemption.
- **Side effects** – Slowdown inaathiri tu malicious path, hivyo utendakazi wa jumla wa mfumo hauathiriwi; defenders mara chache watagundua isipokuwa wakiwa wanamonitor namespace growth.
- **Cleanup** – Hifadhi handles za kila directory/object uliyounda ili uweze kuita `NtMakeTemporaryObject`/`NtClose` baadaye. Mnyororo wa directories usio na mipaka unaweza kubaki hata baada ya reboot ikiwa sivyo.

## Defensive notes

- Kernel code inayotegemea named objects inapaswa ku-re-validate security-sensitive state *baada ya* open, au ichukue reference kabla ya check (kufunga TOCTOU gap).
- Tekeleza bounds za juu kwenye OM path depth/length kabla ya kudereference majina yanayodhibitiwa na mtumiaji. Kukataa majina marefu sana kunalazimisha mashambulizi kurudi ndani ya dirisha la microsecond.
- Instrument namespace growth ya object manager (ETW `Microsoft-Windows-Kernel-Object`) kugundua mnyororo wa maelfu ya components yanayoshukiwa chini ya `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
