# Object Manager Slow Paths를 통한 Kernel Race Condition Exploitation

{{#include ../../banners/hacktricks-training.md}}

## Race window을 늘리는 것이 중요한 이유

많은 Windows kernel LPE는 `check_state(); NtOpenX("name"); privileged_action();`이라는 고전적인 패턴을 따릅니다. 최신 hardware에서는 cold `NtOpenEvent`/`NtOpenSection`이 짧은 name을 약 2 µs 안에 resolve하므로, secure action이 실행되기 전에 검사된 state를 변경할 시간이 거의 없습니다. 2단계의 Object Manager Namespace (OMNS) lookup이 수십 microseconds가 걸리도록 의도적으로 만들면, attacker는 수천 번의 시도 없이도 원래는 불안정한 race에서 일관되게 승리할 수 있을 만큼 충분한 시간을 확보합니다.<sup>[[1]](#references)</sup>

## Object Manager lookup internals 간단 정리

* **OMNS structure** – `\BaseNamedObjects\Foo`와 같은 name은 directory 단위로 resolve됩니다. 각 component마다 kernel은 *Object Directory*를 찾거나 열고 Unicode string을 비교해야 합니다. 이동 중에 symbolic link(예: drive letter)가 traverse될 수도 있습니다.
* **UNICODE_STRING limit** – OM path는 `Length`가 16-bit value인 `UNICODE_STRING` 내부에 저장됩니다. 절대적인 limit은 65 535 bytes(32 767 UTF-16 codepoints)입니다. `\BaseNamedObjects\`와 같은 prefix를 사용해도 attacker는 여전히 약 32 000개의 character를 제어할 수 있습니다.
* **Attacker prerequisites** – 누구나 `\BaseNamedObjects`와 같은 writable directory 아래에 object를 생성할 수 있습니다. vulnerable code가 해당 directory 내부의 name을 사용하거나, 그곳으로 연결되는 symbolic link를 follow하는 경우 attacker는 special privilege 없이 lookup performance를 제어할 수 있습니다.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Single maximal component

component를 resolve하는 비용은 대략 그 길이에 선형 비례합니다. kernel이 parent directory의 모든 entry에 대해 Unicode comparison을 수행해야 하기 때문입니다. 길이가 32 kB인 name으로 event를 생성하면 Windows 11 24H2(Snapdragon X Elite testbed)에서 `NtOpenEvent` latency가 약 2 µs에서 즉시 약 35 µs로 증가합니다.
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*실용적인 참고 사항*

- named kernel object(events, sections, semaphores…)를 사용하면 길이 제한에 도달할 수 있습니다.
- Symbolic link 또는 reparse point를 짧은 “victim” 이름에서 이 거대한 component로 연결하면 slowdown이 투명하게 적용됩니다.
- 모든 것이 user-writable namespace에 존재하므로 payload는 standard user integrity level에서 작동합니다.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Deep recursive directories

더 공격적인 variant는 수천 개의 directory chain(`\BaseNamedObjects\A\A\...\X`)을 할당합니다. 각 hop은 directory resolution logic(ACL checks, hash lookups, reference counting)을 트리거하므로 level당 latency가 단일 string compare보다 높습니다. 동일한 `UNICODE_STRING` size 제한으로 약 16,000개 level을 사용하면, empirical timing은 긴 single component로 달성한 35 µs barrier를 초과합니다.
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

* 부모 디렉터리가 중복을 거부하기 시작하면 레벨마다 문자(`A/B/C/...`)를 번갈아 사용합니다.
* exploitation 후 체인을 깔끔하게 삭제하여 namespace를 오염시키지 않도록 handle 배열을 유지합니다.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – shadow 디렉터리, hash 충돌 및 symlink 재해석 (마이크로초가 아닌 수분)

Object 디렉터리는 **shadow 디렉터리**(fallback lookup)와 항목용 bucket 기반 hash table을 지원합니다. 이 둘과 64-component symbolic-link reparse 제한을 함께 악용하면 `UNICODE_STRING` 길이를 초과하지 않고 slowdown을 크게 증폭할 수 있습니다.

1. `\BaseNamedObjects` 아래에 `A`(shadow)와 `A\A`(target) 같은 두 디렉터리를 생성합니다. 첫 번째 디렉터리를 shadow 디렉터리로 사용하여 두 번째 디렉터리를 생성하면(`NtCreateDirectoryObjectEx`), `A`에서 lookup이 실패할 경우 `A\A`로 fallback됩니다.
2. 각 디렉터리를 동일한 hash bucket에 들어가는 **충돌하는 이름** 수천 개로 채웁니다(예: 후행 숫자를 변경하면서도 동일한 `RtlHashUnicodeString` 값을 유지). 이제 lookup은 단일 디렉터리 내부에서 O(n) 선형 검색으로 저하됩니다.
3. 긴 `A\A\…` suffix로 반복해서 reparse되는 약 63개의 **Object Manager symbolic link** 체인을 구축하여 reparse budget을 소모합니다. 각 reparse는 최상위부터 parsing을 다시 시작하므로 collision cost가 증폭됩니다.
4. 최종 component(`...\\0`)의 lookup은 디렉터리당 16 000개의 collision이 존재할 때 Windows 11에서 **수분**이 걸리며, one-shot kernel LPE에서 race를 사실상 확실하게 승리할 수 있습니다.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*중요한 이유*: 몇 분 동안의 slowdown은 one-shot race 기반 LPE를 deterministic exploit로 전환합니다.<sup>[[1]](#references)</sup>

### 2025 retest notes & ready-made tooling

- James Forshaw는 Windows 11 24H2 (ARM64)에서 업데이트된 timing과 함께 이 technique을 다시 공개했습니다. Baseline open은 여전히 약 2 µs이며, 32 kB component는 이를 약 35 µs로 증가시킵니다. 또한 shadow-dir + collision + 63-reparse chain은 여전히 약 3 분에 도달하여, 해당 primitive이 최신 build에서도 유지됨을 확인했습니다. Source code와 perf harness는 업데이트된 Project Zero post에 있습니다.<sup>[[1]](#references)</sup>
- 공개된 `symboliclink-testing-tools` bundle을 사용하여 setup을 script로 자동화할 수 있습니다. `CreateObjectDirectory.exe`로 shadow/target pair를 생성하고, `NativeSymlink.exe`를 loop에서 실행하여 63-hop chain을 생성합니다. 이를 통해 직접 작성한 `NtCreate*` wrapper를 사용할 필요가 없으며 ACL도 일관되게 유지됩니다.<sup>[[2]](#references)</sup>

## Measuring your race window

exploit 내부에 간단한 harness를 삽입하여 victim hardware에서 window가 얼마나 커지는지 측정합니다. 아래 snippet은 target object를 `iterations`번 open하고 `QueryPerformanceCounter`를 사용하여 open당 평균 cost를 반환합니다.<sup>[[1]](#references)</sup>
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
결과는 race orchestration 전략에 직접 반영됩니다(예: 필요한 worker thread 수, sleep interval, 공유 상태를 얼마나 일찍 전환해야 하는지).

## Exploitation workflow

1. **취약한 open 찾기** – symbols, ETW, hypervisor tracing 또는 reversing을 사용해 kernel path를 추적하여, user-writable directory의 attacker-controlled name 또는 symbolic link를 순회하는 `NtOpen*`/`ObOpenObjectByName` 호출을 찾습니다.
2. **해당 name을 slow path로 교체**
- `\BaseNamedObjects`(또는 다른 writable OM root) 아래에 긴 component 또는 directory chain을 생성합니다.
- name the kernel expects가 이제 slow path로 resolve되도록 symbolic link를 생성합니다. 원래 target을 건드리지 않고 vulnerable driver의 directory lookup을 해당 구조로 지정할 수 있습니다.
3. **race 트리거**
- Thread A(victim)가 vulnerable code를 실행하고 slow lookup 내부에서 block됩니다.
- Thread B(attacker)가 Thread A가 점유된 동안 guarded state를 전환합니다(예: file handle 교체, symbolic link 재작성, object security 전환).
- Thread A가 재개되어 privileged action을 수행하면 stale state를 확인하고 attacker-controlled operation을 수행합니다.
4. **정리** – 의심스러운 artifact를 남기거나 정상적인 IPC 사용자를 방해하지 않도록 directory chain과 symbolic link를 삭제합니다.<sup>[[1]](#references)</sup>

## Applied chain: mutable Cloud Files placeholders + Object Manager path switching

[RoguePlanet (CVE-2026-50656)](https://github.com/MSNightmare/ShieldBreak)의 bypass로 공개된 [ShieldBreak](https://github.com/MSNightmare/ShieldBreak)는 privileged scanner가 logical file의 한 representation을 분류하도록 한 다음, remediation이 이를 사용하기 전에 해당 파일의 bytes와 namespace resolution을 모두 변경하는 더 광범위한 exploitation pattern을 보여줍니다. PoC는 Cloud Files hydration TOCTOU, Object Manager shadow-directory fallback, CLFS-generated-name capture, local administrative-share link를 결합하여 Defender cleanup을 protected DLL write로 전환합니다.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Substitute content through Cloud Files hydration

attacker-writable directory를 Cloud Files sync root로 등록하고, `CF_CALLBACK_TYPE_FETCH_DATA` callback을 연결한 다음, EICAR ZIP과 같은 deterministic detection trigger와 advertised size가 일치하는 placeholder를 생성합니다. 첫 번째 fetch는 trigger를 반환하고 callback state를 전환하며, 이후 fetch는 payload를 반환합니다. scanner가 첫 번째 representation을 분류한 후 transfer key를 가져오고 payload-sized metadata로 hydration을 재시작한 다음, hydration을 EOF까지 강제합니다.<sup>[[4]](#references)</sup>
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
보안 경계는 scan, verdict, remediation이 pathname 또는 placeholder identity만 참조하는 경우 무너집니다. 어느 쪽도 이후 hydration 과정에서 검사된 bytes가 반환된다는 것을 보장하지 않습니다.<sup>[[4]](#references)</sup>

### 2. shadow-directory fallback을 통해 invariant path 전환

`NtCreateDirectoryObjectEx`를 사용해 대상 Object Manager directory와 두 번째 directory를 생성하고, 대상 handle을 shadow/fallback directory로 전달합니다. 두 resolution layer에 동일한 이름의 `WD_SCAN` entry를 배치합니다. visible entry는 일반 working directory를 가리키고, fallback entry는 `\CLFS\??\<working-directory>`를 가리키도록 합니다. 아래의 invariant path만 Defender에 제공하면, operation이 활성 상태일 때 visible link를 삭제하는 순간 동일한 string이 CLFS-backed entry로 fall through합니다.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
이는 조회 속도를 늦추기 위해서만 shadow directories를 사용하는 것과는 다릅니다. 공격자는 문자열을 수정하지 않고도 이전에 허용된 경로의 **의미**를 변경합니다.<sup>[[4]](#references)</sup>

### 3. 생성된 이름을 캡처하고 파일명별 link 설치

`ReadDirectoryChangesW`로 작업 디렉터리를 모니터링합니다. 첫 번째 `FILE_ACTION_ADDED`가 발생하면 표시된 디렉터리에서 `WD_SCAN` link를 제거하여 fallback lookup을 활성화합니다. 두 번째로 생성된 파일명을 캡처하고, 해당 CLFS 관련 파일을 연 다음 `LockFileEx`로 `0..MAXLONGLONG` 범위를 잠급니다. 권한 있는 작업이 중단된 동안, 표시된 디렉터리의 `WD_SCAN`을 실제 Object Manager 디렉터리로 교체하고 관찰된 파일명으로 명명된 child symbolic link를 생성합니다(PoC는 파일명의 마지막 네 문자를 제거합니다). 이를 local SMB를 통해 보호된 destination으로 가리킵니다:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
권한이 없는 프로세스는 해당 대상에 직접 쓸 수 없지만, Defender의 SYSTEM context는 loopback administrative share를 traverse할 수 있습니다. 생성된 이름의 관찰과 filename-specific Object Manager link를 결합하면 remediation artifact를 사전에 예측할 필요가 없습니다.<sup>[[4]](#references)</sup>

### 4. cleanup race를 안정화하고 privileged loader 트리거

Scanning 전에 PoC는 유효한 PE(`ntdll.dll`)를 placeholder의 `:stream` NTFS alternate data stream에 저장합니다. Redirection이 보호된 base file을 생성한 후, `phoneinfo.dll:stream`을 execute access로 열고 cleanup이 재개되는 동안 `PAGE_EXECUTE_READ | SEC_IMAGE` mapping을 유지합니다. 활성 상태인 file/section objects는 최종 race 중 deletion 또는 replacement를 제한합니다. 재시작된 hydration은 이제 EICAR 대신 payload DLL을 반환하므로, 보호된 base file에는 attacker-controlled code가 포함됩니다.<sup>[[4]](#references)</sup>

이후 protected write는 `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` 아래에 조작된 `Report.wer`를 배치하고 Task Scheduler COM API를 통해 `\Microsoft\Windows\Windows Error Reporting\QueueReporting`을 호출하여 SYSTEM execution으로 전환됩니다. 이 chain에서 privileged WER processing은 삽입된 `C:\Windows\System32\phoneinfo.dll`을 load하며, named-pipe connection은 payload execution signal로 사용됩니다.<sup>[[4]](#references)</sup>

### Detection pivots

유용한 correlation은 단일 temporary filename보다 구체적이며, chain의 모든 namespace transition을 포괄합니다.<sup>[[4]](#references)</sup>

- 새로 등록된 Cloud Files provider 이후 동일한 placeholder에서 EICAR detection 및 `CF_OPERATION_TYPE_RESTART_HYDRATION` 발생.
- `WD_TARGET_*`, `WD_SHADOW_*`, 또는 `WD_SCAN`을 포함하는 Object Manager paths. 특히 `\\.\globalroot\BaseNamedObjects\Restricted\` 아래의 scan path.
- CLFS file creation 이후 exclusive whole-file lock 및 privileged security process에서 `\\127.0.0.1\C$\Windows\System32\*.dll`로의 loopback access 발생.
- NTFS ADS와 함께 System32 DLL 생성 후 stream에 대한 `SEC_IMAGE` mapping 발생.
- attacker-created WER queue entry 이후 `\Microsoft\Windows\Windows Error Reporting\QueueReporting`의 비정상적인 manual run 및 삽입된 DLL의 image load 발생.

## Applied chain: privileged remediation에 대한 oplock-gated mount-point switch

privileged scanner가 attacker-controlled file을 검사한 다음, validated handles를 계속 사용하지 않고 **pathname**을 다시 열어 remediation할 때 재사용 가능한 LPE pattern이 나타납니다. FalconFlank는 CrowdStrike Falcon의 Office macro-removal workflow를 대상으로 하는 public example입니다. 해당 repository는 관련 policy가 활성화된 Windows 11 25H2 및 Windows Server 2025에서 테스트했다고 주장하지만, CVE, affected-build range, vendor advisory 또는 patch status를 공개하지 않았습니다. 따라서 product-specific claim은 검증되지 않았으며 build에 따라 달라질 수 있는 것으로 취급해야 합니다.<sup>[[5]](#references)[[6]](#references)</sup>

### Race layout

1. 의도한 destination에서 최종 relative name이 유용하도록 writable tree를 구성합니다. 이 example은 `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll`을 사용하지만, 처음에는 PE DLL이 아닌 OLE macro document를 `bcrypt.dll`에 씁니다. Content-based detection이 remediation을 trigger하며, attacker-controlled basename은 이후 side-load를 위해 유지됩니다.<sup>[[5]](#references)</sup>
2. broad sharing 및 `FILE_OPEN_REPARSE_POINT`를 사용하여 directories를 열고, `FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE`, `REQUEST_OPLOCK_INPUT_FLAG_REQUEST`로 trigger에 asynchronous RH oplock을 요청합니다. overlapped event를 기다린 후 해당 completion을 path-switch cue로 사용합니다. RH oplock-break notification은 advisory일 뿐 모든 conflicting operation이 block되었다는 증거가 아니므로, exploitability는 여전히 victim의 정확한 open/remediation sequence에 따라 달라집니다.<sup>[[5]](#references)[[7]](#references)</sup>
3. break 이후 `FileDispositionInformationEx` (information class 64)를 사용하여 delete 및 POSIX-semantics flags와 함께 leaf directory를 제거하고 handle을 close한 다음, `FSCTL_SET_REPARSE_POINT_EX`로 비어 있는 parent에 `IO_REPARSE_TAG_MOUNT_POINT`를 적용합니다. mount point는 변경되지 않은 suffix를 `\\SystemRoot\\System32\\WindowsPowerShell`과 같은 protected tree로 redirect합니다. directory가 비어 있지 않으면 reparse point 설정이 실패하므로, 앞선 deletion step이 필요합니다.<sup>[[5]](#references)[[8]](#references)</sup>
4. privileged workflow를 재개합니다. directory chain과 최종 object가 이전에 검사한 것과 동일하다는 점을 입증하지 않고 string을 다시 resolve하면, 동일한 logical pathname이 이제 attacker가 선택한 protected directory에 도달합니다. example에서는 original process에서 `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`을 read/write로 다시 열어 성공 여부를 테스트합니다. 이를 통해 confused-deputy write primitive와 이후 code-execution stage를 구분할 수 있습니다.<sup>[[5]](#references)</sup>
5. 결과 file을 실제 DLL로 교체하고 privileged loader를 activate합니다. PoC는 `CreateTransaction` + `CreateFileTransacted`를 사용하고, file을 truncate한 다음 DLL 크기의 replacement를 mapping하고 PE를 copy한 뒤 commit합니다. TxF는 file handle 및 이후 handle-based operations를 transaction에 bind하지만, 이는 privilege boundary failure의 원인이 아니라 race 이후의 replacement mechanism입니다.<sup>[[5]](#references)[[9]](#references)</sup>
6. 마지막으로 planted adjacent filename을 probe하는 executable을 가진 기존 privileged scheduled task를 실행합니다. FalconFlank는 `\\Microsoft\\Windows\\Application Experience\\MareBackup`을 invoke하고, DLL이 `\\??\\pipe\\FALCONFLANK`에 connect할 때까지 기다린 다음 planted file을 삭제합니다. task name만으로 특정 resulting token을 가정하지 말고, 테스트한 build에서 launched process, module path, integrity level 및 token을 확인해야 합니다.<sup>[[5]](#references)</sup>

따라서 핵심 audit question은 “service가 original input path를 validate하는가?”가 아니라 “모든 privileged mutation이 validation된 동일한 opened file 및 directory objects에 계속 bind되어 있는가?”입니다. check와 use 사이에서 handles를 유지하고, trusted directory handle을 기준으로 child objects를 열며, 예상치 못한 reparse tags를 거부하고, mutation 전에 file identity를 재검증하면 이 pathname-substitution bug class를 차단할 수 있습니다.<sup>[[1]](#references)[[8]](#references)</sup>

### Detection 및 PoC triage

High-signal detection은 namespace transition과 privileged consumer를 correlation합니다. GUID로 명명된 temporary tree에서 DLL basename 아래에 있는 OLE header, oplock break, leaf directory의 POSIX-style removal, protected Windows directory를 대상으로 하는 mount point 생성, 그리고 해당 destination 아래 동일 basename의 생성 또는 modification을 함께 확인합니다. public example의 경우 `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`, `MareBackup`의 manual execution 및 `FALCONFLANK` named pipe를 더 좁은 pivot으로 추가할 수 있지만, 어느 하나만으로는 충분하지 않습니다.<sup>[[5]](#references)</sup>

PoC를 재현할 때는 published source의 세 가지 reliability defect를 고려해야 합니다. embedded byte-array pointer를 file handle 대신 사용하여 `FlushFileBuffers`를 호출하고, `GetFolder`, `GetTask`, `Run` 이후 stale `HRESULT`를 검사하며, directory deletion, reparse creation, oplock event 및 pipe connection에 대해 unbounded retry/wait loops를 사용합니다.<sup>[[5]](#references)</sup>

## Operational considerations

- **Combine primitives** – `UNICODE_STRING` size를 모두 사용할 때까지 directory chain의 *각 level마다* 긴 이름을 사용하여 latency를 더 높일 수 있습니다.
- **One-shot bugs** – 확장된 window가 수십 microseconds에서 수분까지 늘어나므로, CPU affinity pinning 또는 hypervisor-assisted preemption과 결합하면 “single trigger” bugs가 현실적이 됩니다.
- **Side effects** – slowdown은 malicious path에만 영향을 주므로 전체 system performance는 영향을 받지 않습니다. defenders가 namespace growth를 monitor하지 않는 한 알아차리기 어렵습니다.
- **Cleanup** – 생성한 모든 directory/object에 대한 handles를 유지하여 이후 `NtMakeTemporaryObject`/`NtClose`를 호출할 수 있도록 합니다. 그렇지 않으면 unbounded directory chains가 reboot 이후에도 남을 수 있습니다.
- **File-system races** – vulnerable path가 최종적으로 NTFS를 통해 resolve된다면, OM slowdown이 실행되는 동안 backing file에 Oplock(예: 동일한 toolkit의 `SetOpLock.exe`)을 설정할 수 있습니다. 이를 통해 OM graph를 변경하지 않고 consumer를 추가 milliseconds 동안 freeze할 수 있습니다.<sup>[[2]](#references)</sup>

## Defensive notes

- Named objects에 의존하는 kernel code는 open 이후 security-sensitive state를 다시 validate하거나, check 전에 reference를 획득하여 TOCTOU gap을 닫아야 합니다.
- User-controlled names를 dereference하기 전에 OM path depth/length에 upper bound를 적용합니다. 지나치게 긴 names를 거부하면 attackers를 microsecond window로 되돌릴 수 있습니다.
- Object manager namespace growth를 계측하여(`Microsoft-Windows-Kernel-Object` ETW) `\BaseNamedObjects` 아래의 의심스러운 수천 개 component chain을 탐지합니다.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Path Lookups를 통한 Race Conditions 승리](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - Transactional NTFS 사용 방법](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
