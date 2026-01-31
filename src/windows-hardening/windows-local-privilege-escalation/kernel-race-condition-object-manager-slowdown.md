# Object Manager Slow Paths를 통한 커널 레이스 컨디션 익스플로잇

{{#include ../../banners/hacktricks-training.md}}

## 레이스 윈도우를 늘리는 것이 중요한 이유

많은 Windows 커널 LPEs는 고전적인 패턴 `check_state(); NtOpenX("name"); privileged_action();`을 따른다. 최신 하드웨어에서 cold `NtOpenEvent`/`NtOpenSection`은 짧은 이름을 약 2 µs 내에 해석해 검사된 상태를 뒤집을 거의 시간이 남지 않는다. 2단계에서 Object Manager Namespace (OMNS) 조회를 일부러 수십 마이크로초로 지연시키면, 공격자는 수천 번의 시도 없이도 일관되게 불안정한 레이스를 이길 수 있을 만큼의 시간을 확보한다.

## Object Manager 조회 내부 구조 요약

* **OMNS structure** – `\BaseNamedObjects\Foo` 같은 이름은 디렉터리 단위로 해석된다. 각 컴포넌트는 커널이 *Object Directory*를 찾아 열고 Unicode 문자열을 비교하게 만든다. 경로 중간에 심볼릭 링크(예: 드라이브 레터)가 따라질 수 있다.
* **UNICODE_STRING limit** – OM paths는 `UNICODE_STRING` 안에 담기며, 그 `Length`는 16비트 값이다. 절대 한계는 65 535 바이트(32 767 UTF-16 코드포인트)이다. `\BaseNamedObjects\` 같은 접두사를 고려해도 공격자는 여전히 ≈32 000 문자를 제어할 수 있다.
* **Attacker prerequisites** – 모든 사용자는 `\BaseNamedObjects` 같은 쓰기 가능한 디렉터리 아래에 객체를 생성할 수 있다. 취약한 코드가 그 안의 이름을 사용하거나 그곳으로 연결되는 심볼릭 링크를 따라갈 때, 공격자는 특별한 권한 없이도 조회 성능을 제어할 수 있다.

## Slowdown primitive #1 – Single maximal component

컴포넌트를 해석하는 비용은 대략 길이에 선형적으로 증가한다. 이는 커널이 부모 디렉터리의 모든 항목에 대해 Unicode 비교를 수행해야 하기 때문이다. 32 kB 길이의 이름으로 이벤트를 생성하면 `NtOpenEvent` 지연시간이 즉시 약 2 µs에서 약 35 µs로 증가한다(Windows 11 24H2, Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*실용적인 노트*

- 길이 제한은 어떤 named kernel object (events, sections, semaphores…)를 사용해도 도달할 수 있다.
- Symbolic links 또는 reparse points는 짧은 “victim” 이름을 이 거대한 컴포넌트로 가리키게 하여 slowdown이 투명하게 적용되게 할 수 있다.
- 모든 것이 user-writable namespaces에 존재하므로 payload는 standard user integrity level 권한에서 동작한다.

## Slowdown primitive #2 – Deep recursive directories

좀 더 공격적인 변형은 수천 개의 디렉터리 체인(`\BaseNamedObjects\A\A\...\X`)을 할당한다. 각 단계는 directory resolution logic (ACL checks, hash lookups, reference counting)을 트리거하므로, 레벨당 지연은 단일 문자열 비교보다 크다. ~16 000 레벨(같은 `UNICODE_STRING` 크기에 의해 제한됨)에서는 실험적 측정값이 긴 단일 컴포넌트로 달성한 35 µs 장벽을 초과한다.
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

* 상위 디렉터리가 중복을 거부하기 시작하면 각 레벨마다 문자를 교대로 사용하세요 (`A/B/C/...`).
* handle array를 유지하여 exploit 후 체인을 깔끔하게 삭제해 네임스페이스 오염을 방지하세요.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories는 항목에 대해 **shadow directories** (fallback lookups)와 버킷화된 해시 테이블을 지원합니다. 두 기능과 64-컴포넌트 symbolic-link reparse 제한을 함께 악용하면 `UNICODE_STRING` 길이를 초과하지 않으면서 지연을 배가시킬 수 있습니다:

1. `\BaseNamedObjects` 아래에 디렉터리 두 개를 만듭니다(예: `A` (shadow)와 `A\A` (target)). 두 번째는 첫 번째를 shadow directory로 사용하여 (`NtCreateDirectoryObjectEx`) 생성하세요. 이렇게 하면 `A`에서 찾을 수 없는 조회가 `A\A`로 넘어갑니다.
2. 각 디렉터리를 동일한 해시 버킷에 들어가는 수천 개의 **colliding names**으로 채우세요(예: `RtlHashUnicodeString` 값은 동일하게 유지하고 후행 숫자만 변경). 이렇게 하면 조회가 단일 디렉터리 내에서 O(n) 선형 스캔으로 저하됩니다.
3. 약 63개의 **object manager symbolic links**로 체인을 만들어 반복적으로 긴 `A\A\…` 접미사로 reparse하여 reparse 예산을 소모하세요. 각 reparse는 파싱을 처음부터 다시 시작해 collision 비용을 배가시킵니다.
4. 디렉터리당 16 000개의 충돌이 있을 때 최종 구성요소(`...\\0`) 조회는 Windows 11에서 **분 단위**가 되며, 이는 일회성 kernel LPEs에 대해 사실상 보장된 레이스 승리를 제공합니다.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Why it matters*: 분 단위의 지연은 one-shot race-based LPEs를 결정적 exploits로 바꿉니다.

## 레이스 윈도우 측정

exploit 내부에 간단한 harness를 삽입해 대상 하드웨어에서 윈도우가 얼마나 커지는지 측정하세요. 아래 스니펫은 대상 객체를 `iterations`번 열고 `QueryPerformanceCounter`를 사용해 오픈당 평균 비용을 반환합니다.
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
결과는 레이스 오케스트레이션 전략(예: 필요한 worker 스레드 수, sleep 간격, 공유 상태를 언제 얼마나 빨리 뒤집어야 하는지)에 직접 반영된다.

## 익스플로잇 워크플로우

1. **Locate the vulnerable open** – 심볼, ETW, 하이퍼바이저 트레이싱 또는 리버싱을 통해 커널 경로를 추적하여 공격자가 제어하는 이름이나 사용자 쓰기 가능한 디렉토리에 있는 심볼릭 링크를 순회하는 `NtOpen*`/`ObOpenObjectByName` 호출을 찾는다.
2. **Replace that name with a slow path**
- `\BaseNamedObjects`(또는 다른 쓰기 가능한 OM 루트) 아래에 긴 컴포넌트나 디렉토리 체인을 생성한다.
- 심볼릭 링크를 생성해 커널이 기대하는 이름이 이제 느린 경로로 해석되도록 한다. 원래 대상은 건드리지 않고도 취약 드라이버의 디렉토리 조회를 당신의 구조로 향하게 할 수 있다.
3. **Trigger the race**
- Thread A (victim)는 취약한 코드를 실행하고 느린 조회 안에서 블록된다.
- Thread B (attacker)는 Thread A가 점유한 동안 가드된 상태(예: 파일 핸들 교체, 심볼릭 링크 재작성, 객체 보안 토글)를 뒤바꾼다.
- Thread A가 재개되어 특권 동작을 수행할 때 오래된 상태를 관찰하고 공격자가 제어하는 동작을 수행한다.
4. **Clean up** – 의심스러운 아티팩트가 남거나 정상적인 IPC 사용자를 방해하지 않도록 디렉토리 체인과 심볼릭 링크를 삭제한다.

## 운영상 고려사항

- **Combine primitives** – 디렉토리 체인에서 레벨별로 긴 이름을 사용할 수 있어 `UNICODE_STRING` 크기를 소진할 때까지 지연을 더욱 늘릴 수 있다.
- **One-shot bugs** – 확장된 윈도우(수십 마이크로초에서 분 단위)는 CPU affinity 고정이나 하이퍼바이저 지원 선점과 결합하면 “단일 트리거” 버그를 현실적으로 만든다.
- **Side effects** – 지연은 악의적 경로에만 영향을 주므로 전체 시스템 성능에는 거의 영향이 없고, 네임스페이스 증가를 모니터링하지 않는 한 수비자는 거의 알아차리지 못한다.
- **Cleanup** – 생성한 모든 디렉토리/객체에 대한 핸들을 유지하여 이후에 `NtMakeTemporaryObject`/`NtClose`를 호출할 수 있도록 한다. 그렇지 않으면 무한한 디렉토리 체인이 재부팅 후에도 남을 수 있다.

## 방어적 메모

- 명명된 객체에 의존하는 커널 코드는 open 이후에 보안 민감 상태를 재검증하거나, 검사 전에 레퍼런스를 획득하여 TOCTOU 갭을 메워야 한다.
- 사용자 제어 이름을 역참조하기 전에 OM 경로 깊이/길이에 상한을 강제하라. 지나치게 긴 이름을 거부하면 공격자를 마이크로초 창으로 되돌린다.
- 객체 관리자 네임스페이스 증가를 계측(ETW `Microsoft-Windows-Kernel-Object`)하여 `\BaseNamedObjects` 아래의 수천 개 컴포넌트 체인 같은 의심스러운 현상을 탐지하라.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
