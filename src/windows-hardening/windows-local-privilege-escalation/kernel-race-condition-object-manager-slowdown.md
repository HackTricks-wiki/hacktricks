# Object Manager Slow Paths를 통한 Kernel Race Condition Exploitation

{{#include ../../banners/hacktricks-training.md}}

## Race window을 늘리는 것이 중요한 이유

많은 Windows kernel LPE는 고전적인 `check_state(); NtOpenX("name"); privileged_action();` 패턴을 따릅니다. 최신 하드웨어에서는 cold `NtOpenEvent`/`NtOpenSection`이 짧은 이름을 약 2 µs 만에 resolve하므로, secure action이 실행되기 전에 확인된 상태를 변경할 시간이 거의 없습니다. 2단계의 Object Manager Namespace (OMNS) lookup을 의도적으로 수십 마이크로초가 걸리도록 만들면, attacker는 수천 번의 시도 없이도 원래는 불안정한 race에서 일관되게 승리할 수 있을 만큼 충분한 시간을 확보합니다.<sup>[[1]](#references)</sup>

## Object Manager lookup internals 한눈에 보기

* **OMNS structure** – `\BaseNamedObjects\Foo`와 같은 이름은 directory 단위로 resolve됩니다. 각 component마다 kernel은 *Object Directory*를 찾거나 열고 Unicode string을 비교합니다. 도중에 symbolic link(예: drive letter)가 traverse될 수도 있습니다.
* **UNICODE_STRING limit** – OM path는 `Length`가 16비트 값인 `UNICODE_STRING` 내부에 저장됩니다. absolute limit은 65 535 bytes(32 767 UTF-16 codepoints)입니다. `\BaseNamedObjects\`와 같은 prefix를 사용해도 attacker는 여전히 약 32 000 characters를 제어할 수 있습니다.
* **Attacker prerequisites** – 누구나 `\BaseNamedObjects`와 같은 writable directory 아래에 object를 생성할 수 있습니다. vulnerable code가 해당 directory 내부의 이름을 사용하거나, 그곳으로 연결되는 symbolic link를 follow하는 경우 attacker는 special privileges 없이 lookup performance를 제어할 수 있습니다.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – 단일 maximal component

component를 resolve하는 비용은 대략 해당 component의 길이에 비례합니다. kernel이 parent directory의 모든 entry와 Unicode comparison을 수행해야 하기 때문입니다. 이름이 32 kB인 event를 생성하면 Windows 11 24H2(Snapdragon X Elite testbed)에서 `NtOpenEvent` latency가 약 2 µs에서 약 35 µs로 즉시 증가합니다.
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*실전 참고 사항*

- 이름이 지정된 kernel object(events, sections, semaphores…)라면 무엇이든 사용해 length limit에 도달할 수 있습니다.
- Symbolic links 또는 reparse points를 짧은 “victim” 이름에서 이 거대한 component로 연결하면 slowdown이 투명하게 적용됩니다.
- 모든 것이 user-writable namespace에 존재하므로 payload는 standard user integrity level에서 작동합니다.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Deep recursive directories

더 공격적인 변형은 수천 개의 directory로 구성된 chain(`\BaseNamedObjects\A\A\...\X`)을 할당합니다. 각 hop은 directory resolution logic(ACL checks, hash lookups, reference counting)을 트리거하므로 level당 latency가 단일 string compare보다 높습니다. 약 16 000개의 level(동일한 `UNICODE_STRING` size에 의해 제한됨)을 사용하면, empirical timings는 긴 단일 component로 달성한 35 µs barrier를 넘어섭니다.
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

* 부모 디렉터리가 중복을 거부하기 시작하면 레벨마다 문자(`A/B/C/...`)를 번갈아 사용하세요.
* exploitation 후 체인을 깔끔하게 삭제하여 namespace를 오염시키지 않도록 handle 배열을 유지하세요.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (microseconds 대신 minutes)

Object directories는 **shadow directories**(fallback lookups)와 항목용 bucketed hash tables를 지원합니다. 이 둘과 64-component symbolic-link reparse limit을 함께 악용하면 `UNICODE_STRING` 길이를 초과하지 않고 slowdown을 배가할 수 있습니다.

1. `\BaseNamedObjects` 아래에 `A`(shadow)와 `A\A`(target) 같은 두 디렉터리를 생성하세요. 첫 번째 디렉터리를 shadow directory로 사용하여 두 번째 디렉터리를 생성하면(`NtCreateDirectoryObjectEx`), `A`에서 누락된 lookup이 `A\A`로 fall through됩니다.
2. 각 디렉터리를 동일한 hash bucket에 들어가는 **colliding names** 수천 개로 채우세요(예: 동일한 `RtlHashUnicodeString` 값을 유지하면서 끝의 숫자만 변경). 이제 lookup은 단일 디렉터리 내부에서 O(n) linear scan으로 저하됩니다.
3. 긴 `A\A\…` suffix로 반복해서 reparse하는 약 63개의 **object manager symbolic links** 체인을 구성하여 reparse budget을 소모하세요. 각 reparse는 최상위부터 parsing을 다시 시작하므로 collision cost가 배가됩니다.
4. 이제 최종 component(`...\\0`)의 lookup은 각 디렉터리에 16 000개의 collision이 존재할 때 Windows 11에서 **minutes**가 걸리며, one-shot kernel LPE에서 사실상 확실한 race win을 제공합니다.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*중요한 이유*: 수 분간 지속되는 slowdown은 one-shot race-based LPEs를 deterministic exploits로 전환합니다.<sup>[[1]](#references)</sup>

### 2025 재테스트 참고 사항 및 ready-made tooling

- James Forshaw는 Windows 11 24H2 (ARM64)에서 업데이트된 timings와 함께 이 technique을 다시 공개했습니다. Baseline opens는 여전히 약 2 µs이며, 32 kB component를 추가하면 약 35 µs로 증가하고, shadow-dir + collision + 63-reparse chains는 여전히 약 3분에 도달하여 현재 builds에서도 primitives가 유지됨을 확인했습니다. Source code와 perf harness는 업데이트된 Project Zero post에 있습니다.<sup>[[1]](#references)</sup>
- 공개된 `symboliclink-testing-tools` bundle을 사용하여 setup을 script로 자동화할 수 있습니다. `CreateObjectDirectory.exe`로 shadow/target pair를 생성하고, `NativeSymlink.exe`를 loop에서 실행하여 63-hop chain을 생성합니다. 이렇게 하면 직접 작성한 `NtCreate*` wrappers가 필요 없고 ACLs를 일관되게 유지할 수 있습니다.<sup>[[2]](#references)</sup>

## Race window 측정

exploit 내부에 간단한 harness를 추가하여 victim hardware에서 window가 얼마나 커지는지 측정하세요. 아래 snippet은 target object를 `iterations` 횟수만큼 열고 `QueryPerformanceCounter`를 사용하여 open 1회당 평균 cost를 반환합니다.<sup>[[1]](#references)</sup>
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
결과는 race orchestration strategy에 직접 반영됩니다(예: 필요한 worker thread 수, sleep interval, shared state를 얼마나 일찍 전환해야 하는지).

## Exploitation workflow

1. **취약한 open 찾기** – symbols, ETW, hypervisor tracing 또는 reversing을 통해 kernel path를 추적하여, attacker-controlled name 또는 user-writable directory의 symbolic link를 순회하는 `NtOpen*`/`ObOpenObjectByName` 호출을 찾습니다.
2. **해당 name을 slow path로 교체**
- `\BaseNamedObjects`(또는 다른 writable OM root) 아래에 긴 component 또는 directory chain을 생성합니다.
- name the kernel expects가 이제 slow path로 resolve되도록 symbolic link를 생성합니다. 원래 target을 건드리지 않고 취약한 driver의 directory lookup을 생성한 structure로 지정할 수 있습니다.
3. **race 트리거**
- Thread A(victim)가 취약한 code를 실행하고 slow lookup 내부에서 block됩니다.
- Thread B(attacker)가 Thread A가 점유된 동안 guarded state를 전환합니다(예: file handle 교체, symbolic link 재작성, object security 전환).
- Thread A가 재개되어 privileged action을 수행하면 stale state를 확인하고 attacker-controlled operation을 수행합니다.
4. **정리** – 의심스러운 artifact를 남기거나 정상적인 IPC 사용자를 방해하지 않도록 directory chain과 symbolic link를 삭제합니다.<sup>[[1]](#references)</sup>

## Operational considerations

- **Primitive 결합** – `UNICODE_STRING` size 한계에 도달할 때까지 directory chain의 *각 level*에 긴 name을 사용하여 latency를 더욱 높일 수 있습니다.
- **One-shot bug** – 확장된 window(수십 microseconds에서 수분)를 CPU affinity pinning 또는 hypervisor-assisted preemption과 함께 사용하면 “single trigger” bug도 현실적으로 악용할 수 있습니다.
- **Side effects** – slowdown은 malicious path에만 영향을 주므로 전체 system performance는 영향을 받지 않습니다. defenders가 namespace growth를 모니터링하지 않는 한 이를 알아차리는 경우는 드뭅니다.
- **Cleanup** – 생성한 모든 directory/object에 대한 handle을 유지하여 이후 `NtMakeTemporaryObject`/`NtClose`를 호출할 수 있도록 합니다. 그렇지 않으면 제한 없는 directory chain이 reboot 이후에도 남을 수 있습니다.
- **File-system races** – vulnerable path가 최종적으로 NTFS를 통해 resolve되는 경우, OM slowdown이 실행되는 동안 backing file에 Oplock(예: 동일한 toolkit의 `SetOpLock.exe`)을 설정할 수 있습니다. 이렇게 하면 OM graph를 변경하지 않고 consumer를 추가 milliseconds 동안 정지시킬 수 있습니다.<sup>[[2]](#references)</sup>

## Defensive notes

- named object에 의존하는 kernel code는 open 이후 security-sensitive state를 다시 검증하거나, check 전에 reference를 획득해야 합니다(TOCTOU gap 해소).
- user-controlled name을 dereference하기 전에 OM path depth/length에 대한 upper bound를 적용합니다. 지나치게 긴 name을 거부하면 attackers가 microsecond window로 되돌아가게 할 수 있습니다.
- object manager namespace growth를 계측하여 `\BaseNamedObjects` 아래에 의심스러운 수천 개 component로 이루어진 chain을 탐지합니다(ETW `Microsoft-Windows-Kernel-Object`).

## References

- [1] [Project Zero – Windows Exploitation Techniques: Path Lookup을 통한 Race Condition 극복](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
