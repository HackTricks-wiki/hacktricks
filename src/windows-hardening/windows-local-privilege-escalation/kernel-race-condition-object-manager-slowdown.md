# Object Manager Slow Paths를 이용한 커널 레이스 컨디션 익스플로잇

{{#include ../../banners/hacktricks-training.md}}

## 레이스 윈도우를 늘리는 것이 중요한 이유

많은 Windows 커널 LPE는 고전적인 패턴 `check_state(); NtOpenX("name"); privileged_action();`을 따릅니다. 최신 하드웨어에서 cold `NtOpenEvent`/`NtOpenSection`은 짧은 이름을 약 2 µs에 해석하므로, 보안 동작이 실행되기 전에 검사된 상태를 바꿀 거의 시간이 없습니다. 2단계에서 Object Manager Namespace (OMNS) 조회를 수십 마이크로초가 걸리도록 의도적으로 지연시키면, 공격자는 수천 번의 시도가 없어도 불안정한 레이스를 일관되게 승리할 만큼 충분한 시간을 확보합니다.

## Object Manager 조회 내부 동작(요약)

* **OMNS structure** – `\BaseNamedObjects\Foo`와 같은 이름은 디렉터리 단위로 해석됩니다. 각 구성 요소마다 커널은 해당 부모 디렉터리에서 *Object Directory*를 찾거나 열고 유니코드 문자열을 비교합니다. 심볼릭 링크(예: 드라이브 문자)가 경로 중간에 따라 연결될 수 있습니다.
* **UNICODE_STRING limit** – OM 경로는 `Length`가 16비트 값인 `UNICODE_STRING` 내부에 저장됩니다. 절대 한계는 65 535 바이트 (32 767 UTF-16 코드포인트)입니다. `\BaseNamedObjects\` 같은 접두사를 고려해도 공격자는 약 32 000자까지 이름을 제어할 수 있습니다.
* **Attacker prerequisites** – 모든 사용자는 `\BaseNamedObjects` 같은 쓰기 가능한 디렉터리 아래에 객체를 생성할 수 있습니다. 취약한 코드가 내부의 이름을 사용하거나 그곳으로 연결되는 심볼릭 링크를 따를 때, 공격자는 특별한 권한 없이도 조회 성능을 제어할 수 있습니다.

## Slowdown primitive #1 – Single maximal component

컴포넌트를 해석하는 비용은 부모 디렉터리의 모든 엔트리에 대해 유니코드 비교를 수행해야 하기 때문에 길이에 거의 선형적으로 증가합니다. 이름이 32 kB인 이벤트를 생성하면 Windows 11 24H2 (Snapdragon X Elite testbed)에서 `NtOpenEvent` 지연이 약 2 µs에서 약 35 µs로 즉시 증가합니다.
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*실용적인 메모*

- 임의의 이름 있는 커널 객체(events, sections, semaphores…)를 사용해 길이 제한에 도달할 수 있다.
- Symbolic links나 reparse points는 짧은 “victim” 이름을 이 거대한 컴포넌트로 가리키게 하여 느려지는 현상이 투명하게 적용되게 할 수 있다.
- 모든 것이 사용자 쓰기 가능한 네임스페이스에 존재하기 때문에 payload는 표준 사용자 integrity level에서 동작한다.

## Slowdown primitive #2 – Deep recursive directories

A more aggressive variant allocates a chain of thousands of directories (`\BaseNamedObjects\A\A\...\X`). Each hop triggers directory resolution logic (ACL checks, hash lookups, reference counting), so the per-level latency is higher than a single string compare. With ~16 000 levels (limited by the same `UNICODE_STRING` size), empirical timings surpass the 35 µs barrier achieved by long single components.
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

* 상위 디렉터리가 중복을 거부하기 시작하면 각 레벨마다 문자(`A/B/C/...`)를 교대로 사용하세요.
* exploitation 이후 네임스페이스 오염을 피하기 위해 체인을 깔끔하게 삭제할 수 있도록 handle 배열을 유지하세요.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (마이크로초 대신 분 단위)

Object 디렉터리는 **shadow directories** (fallback lookups)와 항목용 버킷형 해시 테이블을 지원합니다. 둘과 64-component symbolic-link reparse limit을 남용하여 `UNICODE_STRING` 길이를 넘기지 않고도 느려지는 효과를 곱할 수 있습니다:

1. `\BaseNamedObjects` 아래에 디렉터리 두 개를 생성하세요. 예: `A` (shadow)와 `A\A` (target). 두 번째는 첫 번째를 shadow directory로 지정하여 생성하세요 (`NtCreateDirectoryObjectEx`), 그러면 `A`에서 누락된 조회는 `A\A`로 이어집니다.
2. 각 디렉터리를 같은 해시 버킷에 들어가도록 수천 개의 **colliding names**로 채우세요(예: `RtlHashUnicodeString` 값은 동일하게 유지하면서 끝자리를 변경). 이제 조회는 단일 디렉터리 내에서 O(n) 선형 스캔으로 악화됩니다.
3. 길이가 약 63인 **object manager symbolic links** 체인을 만들어 반복적으로 긴 `A\A\…` 접미사로 reparse시키며 reparse 예산을 소모하세요. 각 reparse는 파싱을 맨 처음부터 다시 시작해 충돌 비용을 배가시킵니다.
4. 최종 컴포넌트(`...\\0`) 조회는 디렉터리당 16 000개의 충돌이 있을 때 Windows 11에서 **분 단위**가 걸리며, 이는 one-shot kernel LPEs에 대해 사실상 보장된 레이스 승리를 제공합니다.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*중요한 이유*: 수분 길이의 지연은 일회성 race 기반 LPE를 결정론적 익스플로잇으로 바꿉니다.

### 2025 재테스트 노트 & 준비된 도구

- James Forshaw는 Windows 11 24H2 (ARM64)에서 타이밍을 업데이트해 기법을 재게시했습니다. baseline opens는 여전히 약 ~2 µs이고; 32 kB 구성요소는 이를 ~35 µs로 올리며, shadow-dir + collision + 63-reparse chains는 여전히 ~3분에 도달해 해당 프리미티브들이 현재 빌드에서도 유효함을 확인시켜 줍니다. 소스 코드와 perf harness는 갱신된 Project Zero post에 있습니다.
- 공개된 `symboliclink-testing-tools` 번들을 사용해 설정을 스크립트화할 수 있습니다: `CreateObjectDirectory.exe`로 shadow/target 쌍을 생성하고 `NativeSymlink.exe`를 루프에서 실행해 63-홉 체인을 생성합니다. 이렇게 하면 수작업으로 작성한 `NtCreate*` 래퍼를 피하고 ACLs를 일관되게 유지할 수 있습니다.

## 레이스 윈도우 측정

익스플로잇 내부에 간단한 하니스(harness)를 삽입해 피해자 하드웨어에서 윈도우가 얼마나 커지는지 측정하세요. 아래 스니펫은 대상 객체를 `iterations` 번 열고 `QueryPerformanceCounter`를 사용해 열기 당 평균 비용을 반환합니다.
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
결과는 레이스 오케스트레이션 전략(예: 필요한 worker threads 수, sleep 간격, shared state를 얼마나 빨리 바꿔야 하는지)에 직접 반영됩니다.

## 익스플로잇 워크플로우

1. **Locate the vulnerable open** – 심볼, ETW, 하이퍼바이저 추적 또는 리버싱을 통해 커널 경로를 추적하여 공격자가 제어하는 이름이나 사용자 쓰기 가능한 디렉터리의 심볼릭 링크를 탐색하는 `NtOpen*`/`ObOpenObjectByName` 호출을 찾습니다.
2. **Replace that name with a slow path**
- `\BaseNamedObjects`(또는 다른 쓰기 가능한 OM 루트) 아래에 긴 컴포넌트 또는 디렉터리 체인을 생성합니다.
- 커널이 기대하는 이름이 이제 느린 경로로 해석되도록 심볼릭 링크를 만듭니다. 원래 대상에 손대지 않고도 취약 드라이버의 디렉터리 조회를 당신의 구조로 향하게 할 수 있습니다.
3. **Trigger the race**
- Thread A (victim)는 취약 코드를 실행하고 느린 조회 내에서 블록됩니다.
- Thread B (attacker)는 Thread A가 점유된 동안 guarded state를 변경합니다(예: 파일 핸들 교체, 심볼릭 링크 재작성, 객체 보안 토글).
- Thread A가 재개되어 권한 있는 동작을 수행할 때, 오래된 상태를 보고 공격자가 제어하는 작업을 수행합니다.
4. **Clean up** – 의심스러운 아티팩트를 남기거나 정당한 IPC 사용자를 방해하지 않도록 디렉터리 체인과 심볼릭 링크를 삭제합니다.

## 운영상 고려사항

- **Combine primitives** – 디렉터리 체인의 각 레벨에 긴 이름을 사용해 `UNICODE_STRING` 크기를 소진할 때까지 더 높은 지연을 만들 수 있습니다.
- **One-shot bugs** – 확장된 윈도우(수십 마이크로초에서 분)는 'single trigger' 버그를 CPU affinity pinning 또는 하이퍼바이저-지원 선점과 결합하면 현실적으로 만듭니다.
- **Side effects** – 지연은 악의적인 경로에만 영향을 주므로 전체 시스템 성능에는 영향이 없습니다; 수비자는 네임스페이스 성장만 모니터하지 않는 이상 거의 눈치채지 못할 것입니다.
- **Cleanup** – 만든 모든 디렉터리/객체에 대한 핸들을 유지해서 이후에 `NtMakeTemporaryObject`/`NtClose`를 호출할 수 있게 하십시오. 그렇지 않으면 무한정인 디렉터리 체인이 재부팅 후에도 지속될 수 있습니다.
- **File-system races** – 취약 경로가 최종적으로 NTFS를 통해 해석된다면, OM 지연이 실행되는 동안 백킹 파일에 Oplock(예: 같은 툴킷의 `SetOpLock.exe`)을 쌓아 OM 그래프를 변경하지 않고 소비자를 추가로 밀리초 단위로 정지시킬 수 있습니다.

## 방어적 주의사항

- 명명된 객체에 의존하는 커널 코드는 open 이후에 보안에 민감한 상태를 재검증하거나, 검사 전에 레퍼런스를 취해야 합니다(TOCTOU 갭을 닫기 위해).
- 사용자 제어 이름을 역참조하기 전에 OM 경로 깊이/길이에 상한을 적용하세요. 지나치게 긴 이름을 거부하면 공격자를 다시 마이크로초 창으로 몰아넣습니다.
- 객체 관리자 네임스페이스 성장을 계측하라(ETW `Microsoft-Windows-Kernel-Object`) — `\BaseNamedObjects` 아래에 수천 개 구성요소 체인이 의심스럽게 늘어나는 것을 탐지하기 위해.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
