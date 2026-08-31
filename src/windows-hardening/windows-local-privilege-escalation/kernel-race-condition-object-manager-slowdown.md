# Object Manager Slow Paths를 통한 Kernel Race Condition Exploitation

{{#include ../../banners/hacktricks-training.md}}

## Race window을 늘리는 것이 중요한 이유

많은 Windows kernel LPE는 `check_state(); NtOpenX("name"); privileged_action();`이라는 전형적인 패턴을 따릅니다. 최신 hardware에서는 cold `NtOpenEvent`/`NtOpenSection`이 짧은 이름을 약 2 µs 만에 resolve하므로, secure action이 실행되기 전에 checked state를 변경할 시간이 거의 없습니다. 의도적으로 2단계의 Object Manager Namespace (OMNS) lookup이 수십 마이크로초가 걸리도록 만들면, attacker는 수천 번의 시도 없이도 원래는 불안정한 race에서 일관되게 승리할 수 있을 만큼 충분한 시간을 확보합니다.<sup>[[1]](#references)</sup>

## Object Manager lookup internals 간단히 살펴보기

* **OMNS structure** – `\BaseNamedObjects\Foo`와 같은 이름은 directory 단위로 resolve됩니다. 각 component마다 kernel은 *Object Directory*를 찾아 열고 Unicode string을 비교해야 합니다. 경로를 따라 symbolic link(예: drive letter)가 traverse될 수도 있습니다.
* **UNICODE_STRING limit** – OM path는 `Length`가 16-bit 값인 `UNICODE_STRING` 내부에 전달됩니다. absolute limit은 65 535 bytes(32 767 UTF-16 codepoints)입니다. `\BaseNamedObjects\`와 같은 prefix를 사용해도 attacker는 여전히 약 32 000개의 character를 제어할 수 있습니다.
* **Attacker prerequisites** – 모든 user는 `\BaseNamedObjects`와 같은 writable directory 아래에 object를 생성할 수 있습니다. vulnerable code가 해당 directory 내부의 이름을 사용하거나, 그곳으로 연결되는 symbolic link를 follow하는 경우 attacker는 special privilege 없이 lookup performance를 제어할 수 있습니다.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Single maximal component

component를 resolve하는 비용은 길이에 대략 linear하게 비례합니다. kernel이 parent directory의 모든 entry에 대해 Unicode comparison을 수행해야 하기 때문입니다. 이름이 32 kB인 event를 생성하면 Windows 11 24H2(Snapdragon X Elite testbed)에서 `NtOpenEvent` latency가 즉시 약 2 µs에서 약 35 µs로 증가합니다.
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Practical notes*

- 모든 named kernel object(events, sections, semaphores…)를 사용하여 length limit에 도달할 수 있습니다.
- Symbolic links 또는 reparse points를 짧은 “victim” name에서 이 거대한 component로 연결하면 slowdown을 투명하게 적용할 수 있습니다.
- 모든 것이 user-writable namespaces에 존재하므로 payload는 standard user integrity level에서 작동합니다.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Deep recursive directories

더 공격적인 variant는 수천 개의 directories(`\BaseNamedObjects\A\A\...\X`) chain을 할당합니다. 각 hop은 directory resolution logic(ACL checks, hash lookups, reference counting)을 트리거하므로 level당 latency가 단일 string compare보다 높습니다. 약 16,000개 level(동일한 `UNICODE_STRING` size에 의해 제한)을 사용하면 empirical timings가 긴 단일 component로 달성한 35 µs barrier를 초과합니다.
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

* Parent directory가 duplicate를 거부하기 시작하면 level마다 character(`A/B/C/...`)를 번갈아 사용합니다.
* exploitation 후 chain을 clean하게 삭제해 namespace를 오염시키지 않도록 handle array를 유지합니다.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (microseconds 대신 minutes)

Object directories는 **shadow directories**(fallback lookups)와 entries용 bucketed hash tables를 지원합니다. 이 둘과 64-component symbolic-link reparse limit을 함께 abuse하면 `UNICODE_STRING` length를 초과하지 않고 slowdown을 배수로 늘릴 수 있습니다.

1. `\BaseNamedObjects` 아래에 예를 들어 `A`(shadow)와 `A\A`(target), 두 directory를 생성합니다. 첫 번째 directory를 shadow directory로 사용해 두 번째 directory를 생성합니다(`NtCreateDirectoryObjectEx`). 그러면 `A`에서 missing lookup이 `A\A`로 fall through됩니다.
2. 각 directory를 동일한 hash bucket에 들어가는 수천 개의 **colliding names**로 채웁니다(예: 동일한 `RtlHashUnicodeString` value를 유지하면서 trailing digits를 변경). 이제 lookup은 단일 directory 내부에서 O(n) linear scan으로 저하됩니다.
3. 긴 `A\A\…` suffix로 반복해서 reparse하는 약 63개의 **object manager symbolic links** chain을 구축해 reparse budget을 소모합니다. 각 reparse는 top부터 parsing을 재시작하므로 collision cost가 배수로 증가합니다.
4. 이제 final component(`...\\0`)의 lookup은 directory당 16 000개의 collision이 존재할 때 Windows 11에서 **minutes**가 걸리며, one-shot kernel LPE에서 사실상 guaranteed race win을 제공합니다.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*중요한 이유*: 몇 분에 걸친 slowdown은 one-shot race 기반 LPE를 deterministic exploit으로 전환합니다.<sup>[[1]](#references)</sup>

### 2025 재테스트 노트 및 ready-made tooling

- James Forshaw는 Windows 11 24H2 (ARM64)에서 업데이트된 timings와 함께 이 technique을 다시 공개했습니다. Baseline opens는 여전히 약 2 µs이며, 32 kB component를 추가하면 약 35 µs로 증가합니다. 또한 shadow-dir + collision + 63-reparse chains는 여전히 약 3 분에 도달하여, 현재 builds에서도 primitives가 유지됨을 확인했습니다. 소스 코드와 perf harness는 업데이트된 Project Zero post에 있습니다.<sup>[[1]](#references)</sup>
- 공개된 `symboliclink-testing-tools` bundle을 사용해 setup을 script로 작성할 수 있습니다. `CreateObjectDirectory.exe`로 shadow/target pair를 생성하고, `NativeSymlink.exe`를 loop에서 실행해 63-hop chain을 생성합니다. 이렇게 하면 직접 작성한 `NtCreate*` wrappers가 필요 없고 ACL을 일관되게 유지할 수 있습니다.<sup>[[2]](#references)</sup>

## Measuring your race window

victim hardware에서 window가 얼마나 커지는지 측정하려면 exploit 내부에 간단한 harness를 삽입합니다. 아래 snippet은 `QueryPerformanceCounter`를 사용해 target object를 `iterations`회 열고 open당 평균 cost를 반환합니다.<sup>[[1]](#references)</sup>
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
결과는 race orchestration 전략에 직접 반영됩니다(예: 필요한 worker thread 수, sleep interval, shared state를 얼마나 일찍 전환해야 하는지).

## Exploitation workflow

1. **취약한 open 찾기** – symbols, ETW, hypervisor tracing 또는 reversing을 통해 kernel path를 추적하여, user-writable directory의 attacker-controlled name 또는 symbolic link를 순회하는 `NtOpen*`/`ObOpenObjectByName` 호출을 찾습니다.
2. **해당 name을 slow path로 교체**
- `\BaseNamedObjects`(또는 다른 writable OM root) 아래에 긴 component 또는 directory chain을 생성합니다.
- name the kernel expects가 이제 slow path로 resolve되도록 symbolic link를 생성합니다. 원래 target을 건드리지 않고 vulnerable driver의 directory lookup을 해당 구조로 지정할 수 있습니다.
3. **race trigger**
- Thread A(victim)가 vulnerable code를 실행하고 slow lookup 내부에서 block됩니다.
- Thread B(attacker)가 Thread A가 점유된 동안 guarded state를 변경합니다(예: file handle 교체, symbolic link 재작성, object security 전환).
- Thread A가 resume되어 privileged action을 수행하면 stale state를 확인하고 attacker-controlled operation을 수행합니다.
4. **정리** – 의심스러운 artifact를 남기거나 정상적인 IPC 사용자를 방해하지 않도록 directory chain과 symbolic link를 삭제합니다.<sup>[[1]](#references)</sup>

## 적용 chain: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak)는 RoguePlanet(CVE-2026-50656)의 bypass로 공개되었으며, privileged scanner가 logical file의 한 representation을 classify하도록 만든 다음 remediation에서 사용하기 전에 해당 파일의 bytes와 namespace resolution을 모두 변경하는 더 광범위한 exploitation pattern을 보여줍니다. PoC는 Cloud Files hydration TOCTOU, Object Manager shadow-directory fallback, CLFS-generated-name capture, 그리고 local administrative-share link를 결합하여 Defender cleanup을 protected DLL write로 전환합니다.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Cloud Files hydration을 통한 content 대체

attacker-writable directory를 Cloud Files sync root로 register하고, `CF_CALLBACK_TYPE_FETCH_DATA` callback을 연결한 다음, EICAR ZIP과 같은 deterministic detection trigger에 맞는 advertised size를 가진 placeholder를 생성합니다. 첫 번째 fetch는 trigger를 반환하고 callback state를 전환하며, 이후 fetch는 payload를 반환합니다. scanner가 첫 번째 representation을 classify한 후 transfer key를 가져오고 payload-sized metadata로 hydration을 restart한 다음 hydration을 EOF까지 강제로 진행합니다.<sup>[[4]](#references)</sup>
```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```
보안 경계는 scan, verdict, remediation이 pathname 또는 placeholder identity만 참조할 경우 무너진다. 어느 쪽도 이후의 hydration에서 검사된 bytes가 반환된다는 것을 보장하지 않는다.<sup>[[4]](#references)</sup>

### 2. shadow-directory fallback을 통해 invariant path 전환

`NtCreateDirectoryObjectEx`를 사용해 대상 Object Manager directory와 두 번째 directory를 생성하고, 대상 handle을 shadow/fallback directory로 전달한다. 두 resolution layer에 동일한 이름의 `WD_SCAN` entry를 배치한다. visible entry는 일반 working directory를 가리키고, fallback entry는 `\CLFS\??\<working-directory>`를 가리키도록 한다. 아래의 invariant path만 Defender에 제공한다. 작업이 활성화된 동안 visible link를 삭제하면 동일한 문자열이 CLFS-backed entry로 fall through한다.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
이는 lookup을 지연시키기 위해서만 shadow directories를 사용하는 것과는 다릅니다. 공격자는 문자열을 수정하지 않고도 이전에 허용된 path의 **meaning**을 변경합니다.<sup>[[4]](#references)</sup>

### 3. 생성된 name을 캡처하고 filename-specific link 설치

`ReadDirectoryChangesW`로 working directory를 모니터링합니다. 첫 번째 `FILE_ACTION_ADDED`에서 visible `WD_SCAN` link를 제거하여 fallback lookup을 활성화합니다. 두 번째로 생성된 filename을 캡처하고 해당 CLFS-related file을 연 다음, `LockFileEx`로 `0..MAXLONGLONG` 범위를 lock합니다. privileged operation이 stalled된 동안 visible directory의 `WD_SCAN`을 실제 Object Manager directory로 교체하고, 관찰된 filename으로 이름을 지정한 child symbolic link를 생성합니다(PoC는 마지막 네 문자를 제거합니다). 이를 local SMB를 통해 protected destination을 가리키도록 설정합니다:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
권한이 없는 프로세스 자체는 해당 대상에 쓸 수 없지만, Defender의 SYSTEM context는 loopback administrative share를 통과할 수 있습니다. 생성된 이름을 관찰하고 filename-specific Object Manager link를 함께 사용하면 remediation artifact를 미리 예측할 필요가 없습니다.<sup>[[4]](#references)</sup>

### 4. cleanup race를 안정화하고 privileged loader 트리거

스캔 전에 PoC는 유효한 PE(`ntdll.dll`)를 placeholder의 `:stream` NTFS alternate data stream에 저장합니다. redirection이 보호된 base file을 생성한 후에는 `phoneinfo.dll:stream`을 execute access로 열고 `PAGE_EXECUTE_READ | SEC_IMAGE` mapping을 유지한 채 cleanup이 재개되도록 합니다. 이때 살아 있는 file/section object가 최종 race 동안 삭제 또는 교체를 제한합니다. 재시작된 hydration은 이제 EICAR 대신 payload DLL을 반환하므로, 보호된 base file에는 attacker-controlled code가 포함됩니다.<sup>[[4]](#references)</sup>

그런 다음 `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` 아래에 조작된 `Report.wer`를 배치하고 Task Scheduler COM API를 통해 `\Microsoft\Windows\Windows Error Reporting\QueueReporting`을 호출하여 protected write를 SYSTEM execution으로 전환합니다. 이 chain에서 privileged WER processing은 심어진 `C:\Windows\System32\phoneinfo.dll`을 load하며, named-pipe connection은 payload execution signal로 사용됩니다.<sup>[[4]](#references)</sup>

### Detection pivots

유용한 correlation은 단일 temporary filename보다 구체적이며, chain의 모든 namespace transition을 포괄합니다.<sup>[[4]](#references)</sup>

- 새로 등록된 Cloud Files provider 이후 동일한 placeholder에서 EICAR detection 및 `CF_OPERATION_TYPE_RESTART_HYDRATION`이 발생하는 경우
- `WD_TARGET_*`, `WD_SHADOW_*`, 또는 `WD_SCAN`을 포함하는 Object Manager paths, 특히 `\\.\globalroot\BaseNamedObjects\Restricted\` 아래의 scan path
- CLFS file creation 이후 exclusive whole-file lock이 설정되고, privileged security process가 `\\127.0.0.1\C$\Windows\System32\*.dll`에 loopback access하는 경우
- System32 DLL이 NTFS ADS와 함께 생성된 후 stream에 `SEC_IMAGE` mapping이 이루어지는 경우
- attacker-created WER queue entry 이후 `\Microsoft\Windows\Windows Error Reporting\QueueReporting`이 비정상적으로 수동 실행되고 심어진 DLL이 image load되는 경우

## Operational considerations

- **Combine primitives** – `UNICODE_STRING` size를 모두 사용할 때까지 directory chain의 *각 level*에 긴 이름을 사용하여 latency를 더 높일 수 있습니다.
- **One-shot bugs** – 확장된 window(수십 microseconds에서 수분)는 CPU affinity pinning 또는 hypervisor-assisted preemption과 결합할 경우 “single trigger” bugs를 현실적으로 만듭니다.
- **Side effects** – slowdown은 malicious path에만 영향을 주므로 전체 system performance는 영향을 받지 않습니다. defenders가 namespace growth를 monitor하지 않는 한 이를 알아차리는 경우는 드뭅니다.
- **Cleanup** – 생성한 모든 directory/object에 대한 handles를 유지하여 이후 `NtMakeTemporaryObject`/`NtClose`를 호출할 수 있도록 합니다. 그렇지 않으면 무제한 directory chains가 reboot 후에도 남을 수 있습니다.
- **File-system races** – vulnerable path가 최종적으로 NTFS를 통해 resolve된다면, OM slowdown이 실행되는 동안 backing file에 Oplock(예: 동일한 toolkit의 `SetOpLock.exe`)을 설정할 수 있습니다. 이렇게 하면 OM graph를 변경하지 않고 consumer를 추가 milliseconds 동안 freeze할 수 있습니다.<sup>[[2]](#references)</sup>

## Defensive notes

- named objects에 의존하는 Kernel code는 open 이후 security-sensitive state를 다시 validate하거나, check 전에 reference를 획득하여 TOCTOU gap을 해소해야 합니다.
- user-controlled names를 dereference하기 전에 OM path depth/length에 대한 upper bounds를 적용합니다. 지나치게 긴 names를 거부하면 attackers는 microsecond window로 되돌아가야 합니다.
- object manager namespace growth를 계측하여(`Microsoft-Windows-Kernel-Object` ETW) `\BaseNamedObjects` 아래에 수천 개 component로 이루어진 의심스러운 chains를 탐지합니다.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Path Lookups로 Race Conditions에서 승리하기](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
