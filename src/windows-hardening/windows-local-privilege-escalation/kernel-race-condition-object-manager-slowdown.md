# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## 레이스 윈도우를 늘리는 이유

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. On modern hardware a cold `NtOpenEvent`/`NtOpenSection` resolves a short name in ~2 µs, leaving almost no time to flip the checked state before the secure action happens. By deliberately forcing the Object Manager Namespace (OMNS) lookup in step 2 to take tens of microseconds, the attacker gains enough time to consistently win otherwise flaky races without needing thousands of attempts.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Names such as `\BaseNamedObjects\Foo` are resolved directory-by-directory. Each component causes the kernel to find/open an *Object Directory* and compare Unicode strings. Symbolic links (e.g., drive letters) may be traversed en route.
* **UNICODE_STRING limit** – OM paths are carried inside a `UNICODE_STRING` whose `Length` is a 16-bit value. The absolute limit is 65 535 bytes (32 767 UTF-16 codepoints). With prefixes like `\BaseNamedObjects\`, an attacker still controls ≈32 000 characters.
* **Attacker prerequisites** – Any user can create objects underneath writable directories such as `\BaseNamedObjects`. When the vulnerable code uses a name inside, or follows a symbolic link that lands there, the attacker controls the lookup performance with no special privileges.

## Slowdown primitive #1 – 단일 최대 구성 요소

The cost of resolving a component is roughly linear with its length because the kernel must perform a Unicode comparison against every entry in the parent directory. Creating an event with a 32 kB-long name immediately increases the `NtOpenEvent` latency from ~2 µs to ~35 µs on Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*실용 노트*

- 임의의 named kernel object (events, sections, semaphores…)을 사용해 길이 제한에 도달시킬 수 있다.
- Symbolic links 또는 reparse points는 짧은 “victim” 이름을 이 거대한 컴포넌트로 가리켜서 지연이 투명하게 적용되도록 할 수 있다.
- 모든 것이 user-writable namespaces에 존재하기 때문에 payload는 standard user integrity level에서 동작한다.

## Slowdown primitive #2 – Deep recursive directories

더 공격적인 변형은 수천 개의 디렉터리 체인 (`\BaseNamedObjects\A\A\...\X`)을 할당한다. 각 홉은 directory resolution logic (ACL checks, hash lookups, reference counting)을 트리거하므로, 레벨당 지연이 단일 문자열 비교보다 크다. 약 ~16 000 레벨(같은 `UNICODE_STRING` 크기에 의해 제한됨)에서, 실험적 타이밍은 긴 단일 컴포넌트로 달성된 35 µs 장벽을 뛰어넘는다.
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

* 상위 디렉터리가 중복을 거부하기 시작하면 레벨마다 문자를 번갈아 사용하세요 (`A/B/C/...`).
* 핸들 배열을 유지해서 exploitation 후 체인을 깔끔하게 삭제해 네임스페이스 오염을 방지하세요.

## 레이스 윈도우 측정

exploit 내부에 간단한 harness를 삽입하여 피해자 하드웨어에서 윈도우가 얼마나 커지는지 측정하세요. 아래 스니펫은 대상 객체를 `iterations` 번 열고 `QueryPerformanceCounter` 를 사용해 오픈당 평균 비용을 반환합니다.
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

1. **취약한 open 호출 찾기** – symbols, ETW, hypervisor tracing, 또는 reversing을 통해 커널 경로를 추적하여 공격자가 제어하는 이름이나 사용자 쓰기 가능한 디렉터리에 있는 심볼릭 링크를 탐색하는 `NtOpen*`/`ObOpenObjectByName` 호출을 찾는다.
2. **그 이름을 느린 경로로 교체**  
- `\BaseNamedObjects`(또는 다른 쓰기 가능한 OM 루트) 아래에 긴 컴포넌트나 디렉터리 체인을 만든다.  
- 커널이 기대하는 이름이 이제 느린 경로로 해석되도록 심볼릭 링크를 만든다. 원래 대상을 건드리지 않고 취약한 드라이버의 디렉터리 조회를 당신의 구조로 향하게 할 수 있다.
3. **레이스 트리거**  
- Thread A (victim)는 취약 코드를 실행하고 느린 조회 내에서 블록된다.  
- Thread B (attacker)는 Thread A가 점유된 동안 보호된 상태를 바꾼다(예: 파일 핸들 교체, 심볼릭 링크 재작성, 오브젝트 보안 토글 등).  
- Thread A가 재개되어 권한 있는 작업을 수행할 때 오래된 상태를 관찰하고 공격자가 제어하는 작업을 수행한다.
4. **정리** – 의심스러운 흔적을 남기거나 정상적인 IPC 사용자를 방해하지 않도록 디렉터리 체인과 심볼릭 링크를 삭제한다.

## Operational considerations

- **Combine primitives** – 디렉터리 체인의 *per level*에서 긴 이름을 사용하면 UNICODE_STRING 크기가 소진될 때까지 더 높은 지연을 얻을 수 있다.
- **One-shot bugs** – 확장된 윈도우(수십 마이크로초)는 CPU affinity pinning 또는 hypervisor-assisted preemption과 결합하면 “single trigger” 버그를 현실적으로 만든다.
- **Side effects** – 지연은 악성 경로에만 영향을 주므로 전체 시스템 성능에는 영향을 주지 않는다; 수비자는 네임스페이스 증가를 모니터링하지 않는 이상 거의 알아차리지 못한다.
- **Cleanup** – 생성한 모든 디렉터리/오브젝트에 대한 핸들을 유지하여 이후에 `NtMakeTemporaryObject`/`NtClose`를 호출할 수 있도록 하라. 그렇지 않으면 무한한 디렉터리 체인이 재부팅 후에도 남을 수 있다.

## Defensive notes

- 이름 있는 오브젝트에 의존하는 커널 코드는 open *후에* 보안 민감 상태를 재검증하거나, 검사 전에 참조를 취득해야 한다(TOCTOU 갭을 닫음).
- 사용자 제어 이름을 역참조하기 전에 OM 경로 깊이/길이에 대한 상한을 강제하라. 지나치게 긴 이름을 거부하면 공격자는 마이크로초 창으로 되돌아가게 된다.
- 오브젝트 매니저 네임스페이스 성장(ETW `Microsoft-Windows-Kernel-Object`)을 계측하여 `\BaseNamedObjects` 아래 수천 개 구성요소 체인과 같은 의심스러운 상황을 탐지하라.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
