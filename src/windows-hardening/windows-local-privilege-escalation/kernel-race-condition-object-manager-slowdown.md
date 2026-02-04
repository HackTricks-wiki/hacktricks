# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## 레이스 창을 늘리는 것이 중요한 이유

많은 Windows kernel LPE는 고전적인 패턴 `check_state(); NtOpenX("name"); privileged_action();`을 따릅니다. 최신 하드웨어에서 콜드 `NtOpenEvent`/`NtOpenSection`는 짧은 이름을 약 2 µs 안에 해석하므로, 보안 동작이 실행되기 전에 검사된 상태를 변경할 거의 시간이 남지 않습니다. 2단계의 Object Manager Namespace (OMNS) 조회를 수십 마이크로초로 의도적으로 지연시키면, 공격자는 수천 번 시도할 필요 없이 일관되게 불안정한 레이스에서 승리할 충분한 시간을 확보할 수 있습니다.

## Object Manager lookup 내부 동작(요약)

* **OMNS 구조** – `\BaseNamedObjects\Foo`와 같은 이름은 디렉터리별로 순차적으로 해석됩니다. 각 구성 요소마다 커널은 *Object Directory*를 찾거나 열고 Unicode 문자열을 비교합니다. 심볼릭 링크(예: 드라이브 문자)가 경로 상에서 따라갈 수 있습니다.
* **UNICODE_STRING limit** – OM 경로는 `Length`가 16비트 값인 `UNICODE_STRING` 안에 담깁니다. 절대 한계는 65 535 바이트(32 767 UTF-16 코드포인트)입니다. `\BaseNamedObjects\` 같은 접두사를 고려해도 공격자는 여전히 ≈32 000 문자를 제어할 수 있습니다.
* **Attacker prerequisites** – 모든 사용자는 `\BaseNamedObjects` 같은 쓰기 가능한 디렉터리 아래에 객체를 생성할 수 있습니다. 취약한 코드가 그 안의 이름을 사용하거나 그곳으로 연결되는 심볼릭 링크를 따라가면, 공격자는 특권 없이도 조회 성능을 제어할 수 있습니다.

## Slowdown primitive #1 – Single maximal component

구성 요소를 해석하는 비용은 길이에 거의 선형적으로 증가합니다. 그 이유는 커널이 부모 디렉터리의 모든 항목에 대해 Unicode 비교를 수행해야 하기 때문입니다. 이름 길이가 32 kB인 이벤트를 생성하면 `NtOpenEvent`의 지연이 즉시 약 2 µs에서 약 35 µs로 증가합니다 (Windows 11 24H2, Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*실용적인 노트*

- 임의의 named kernel object (events, sections, semaphores…)를 사용해 길이 제한에 도달할 수 있습니다.
- Symbolic links 또는 reparse points는 짧은 “victim” 이름을 이 거대한 컴포넌트로 가리키게 하여 slowdown이 투명하게 적용되도록 할 수 있습니다.
- 모든 것이 user-writable namespaces에 존재하기 때문에, payload는 standard user integrity level에서 동작합니다.

## Slowdown primitive #2 – Deep recursive directories

더 공격적인 변형은 수천 개의 디렉터리 체인(`\BaseNamedObjects\A\A\...\X`)을 할당합니다. 각 홉은 directory resolution logic (ACL checks, hash lookups, reference counting)을 트리거하므로, 레벨당 지연 시간은 단일 문자열 비교보다 큽니다. 동일한 `UNICODE_STRING` 크기로 제한되는 약 ~16 000 레벨에서 경험적 타이밍은 긴 단일 컴포넌트로 달성된 35 µs 장벽을 초과합니다.
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
팁:

* 부모 디렉터리가 중복을 거부하기 시작하면 각 레벨마다 문자(`A/B/C/...`)를 번갈아 사용하세요.
* 핸들 배열을 유지하여 exploitation 후 체인을 깔끔하게 삭제해 네임스페이스 오염을 방지하세요.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories는 **shadow directories** (fallback lookups)와 엔트리를 위한 bucketed hash tables를 지원합니다. 둘과 64-component symbolic-link reparse limit을 악용해 `UNICODE_STRING` 길이를 초과하지 않으면서 slowdown을 곱셈하세요:

1. `\BaseNamedObjects` 아래에 두 디렉터리를 생성하세요. 예: `A` (shadow) 및 `A\A` (target). 두 번째는 첫 번째를 shadow directory로 지정하여(`NtCreateDirectoryObjectEx`) 생성하세요. 이렇게 하면 `A`에서 항목이 없을 때 lookup이 `A\A`로 이어집니다.
2. 각 디렉터리를 동일한 해시 버킷에 들어가는 수천 개의 **colliding names**로 채우세요(예: 동일한 `RtlHashUnicodeString` 값을 유지하면서 끝자리 숫자만 변경). 이 경우 lookup은 단일 디렉터리 내에서 O(n) 선형 스캔으로 저하됩니다.
3. 약 63개의 **object manager symbolic links** 체인을 만들어 반복적으로 긴 `A\A\…` 접미사로 reparse시켜 reparse budget을 소모하세요. 각 reparse는 파싱을 처음부터 다시 시작해 collision 비용을 증가시킵니다.
4. 최종 컴포넌트(`...\\0`)에 대한 lookup은 각 디렉터리에 16 000개의 collisions가 있을 때 Windows 11에서 이제 **분 단위**가 되어, one-shot kernel LPEs에서 사실상 보장된 race 승리를 제공합니다.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*중요한 이유*: 몇 분에 걸친 지연은 one-shot race-based LPEs를 결정적 exploits로 바꿉니다.

## race window 측정하기

exploit 내부에 간단한 하니스 코드를 삽입하여 피해자 하드웨어에서 윈도우가 얼마나 커지는지 측정하세요. 아래 스니펫은 대상 오브젝트를 `iterations`번 열고 `QueryPerformanceCounter`를 사용해 개별 열기당 평균 비용을 반환합니다.
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

1. **Locate the vulnerable open** – 카널 경로를 추적합니다 (symbols, ETW, hypervisor tracing, 또는 reversing 사용). 공격자가 제어하는 이름이나 user-writable 디렉터리의 symbolic link를 순회하는 `NtOpen*`/`ObOpenObjectByName` 호출을 찾으세요.
2. **Replace that name with a slow path**
- `\BaseNamedObjects`(또는 다른 쓰기 가능한 OM 루트) 아래에 긴 컴포넌트 또는 디렉터리 체인을 만듭니다.
- 커널이 기대하는 이름이 이제 느린 경로로 해석되도록 symbolic link를 만듭니다. 원래 대상은 건드리지 않고 취약 드라이버의 디렉터리 조회를 여러분의 구조로 유도할 수 있습니다.
3. **Trigger the race**
- Thread A (victim)는 취약 코드를 실행하고 느린 조회 안에서 블록됩니다.
- Thread B (attacker)는 Thread A가 바쁜 동안 guarded state를 뒤집습니다(예: 파일 핸들 교체, symbolic link 재작성, 객체 보안 토글).
- Thread A가 재개되어 권한 있는 동작을 수행할 때, 오래된(stale) 상태를 관찰하고 공격자가 제어하는 작업을 수행합니다.
4. **Clean up** – 의심스러운 흔적을 남기거나 정상적인 IPC 사용자를 깨뜨리지 않도록 디렉터리 체인과 symbolic link를 삭제합니다.

## Operational considerations

- **Combine primitives** – 디렉터리 체인의 각 레벨마다 긴 이름을 사용하면 `UNICODE_STRING` 크기를 소진할 때까지 지연 시간을 더 늘릴 수 있습니다.
- **One-shot bugs** – 확장된 윈도우(수십 마이크로초에서 수분)는 CPU affinity 고정이나 hypervisor-assisted preemption과 결합하면 “한 번의 트리거” 버그를 현실적으로 만듭니다.
- **Side effects** – 느려지는 효과는 악의적인 경로에만 국한되므로 전체 시스템 성능에는 영향을 거의 주지 않습니다; 방어자는 namespace 증가를 모니터링하지 않으면 거의 눈치채지 못합니다.
- **Cleanup** – 만든 모든 디렉터리/객체에 대한 핸들을 유지하여 이후 `NtMakeTemporaryObject`/`NtClose`를 호출하세요. 그렇지 않으면 무한한 디렉터리 체인이 재부팅 후에도 남을 수 있습니다.

## Defensive notes

- named objects에 의존하는 kernel 코드는 open 이후에 보안에 민감한 상태를 재검증하거나(또는 체크 전에 레퍼런스를 확보) TOCTOU 격차를 메워야 합니다.
- user-controlled 이름을 역참조(dereference)하기 전에 OM 경로 깊이/길이에 대한 상한을 강제하세요. 지나치게 긴 이름을 거부하면 공격자는 마이크로초 창으로 다시 밀려납니다.
- 객체 관리자 네임스페이스의 성장(ETW `Microsoft-Windows-Kernel-Object`)을 계측하여 `\BaseNamedObjects` 아래 수천 개 컴포넌트 체인 같은 의심스러운 증가를 탐지하세요.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
