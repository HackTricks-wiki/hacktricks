# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

`/private/var/vm/swapfile0`과 같은 Swap 파일은 **physical memory가 가득 찼을 때 cache로 사용**됩니다. physical memory에 더 이상 공간이 없으면 해당 데이터가 swap file로 전송된 후, 필요에 따라 다시 physical memory로 가져옵니다. 여러 개의 swap file이 존재할 수 있으며, swapfile0, swapfile1 등의 이름이 사용됩니다.

### Hibernate Image

`/private/var/vm/sleepimage`에 위치한 파일은 **hibernation mode**에서 중요한 역할을 합니다. **OS X가 hibernate 상태가 되면 memory의 데이터가 이 파일에 저장**됩니다. 컴퓨터가 깨어나면 system은 이 파일에서 memory 데이터를 복원하여 사용자가 중단했던 지점부터 계속할 수 있도록 합니다.

현대적인 MacOS system에서는 보안상의 이유로 이 파일이 일반적으로 암호화되어 있으므로 recovery가 어렵다는 점에 유의해야 합니다.

- sleepimage의 encryption이 활성화되어 있는지 확인하려면 `sysctl vm.swapusage` command를 실행할 수 있습니다. 이 command를 통해 파일이 encrypted 상태인지 확인할 수 있습니다.

### Memory Pressure Logs

MacOS system에서 memory와 관련된 또 다른 중요한 파일은 **memory pressure log**입니다. 이러한 log는 `/var/log`에 위치하며 system의 memory 사용량과 pressure event에 대한 자세한 정보를 포함합니다. Memory와 관련된 문제를 진단하거나 system이 시간에 따라 memory를 관리하는 방식을 파악하는 데 특히 유용합니다.

## osxpmem으로 memory dumping

MacOS machine의 memory를 dump하려면 [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)을 사용할 수 있습니다.

**참고**: 현재는 대부분 **legacy workflow**입니다. `osxpmem`은 kernel extension을 load해야 하며, [Rekall](https://github.com/google/rekall) project는 archived 상태이고, 최신 release는 **2017년**에 공개되었으며, 배포된 binary는 **Intel Mac**을 대상으로 합니다. 최신 macOS release, 특히 **Apple Silicon**에서는 modern kernel-extension restrictions, SIP 및 platform-signing requirements로 인해 kext 기반의 full-RAM acquisition이 일반적으로 차단됩니다. 실제로 modern system에서는 whole-RAM image 대신 **process-scoped dump**를 수행하게 되는 경우가 더 많습니다.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
다음 오류가 표시되면: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 다음과 같이 수정할 수 있습니다:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Other errors**는 "Security & Privacy --> General"에서 **kext 로드**를 **허용**하면 해결될 수 있습니다. 그냥 **허용**하세요.

다음 **oneliner**를 사용하여 application을 다운로드하고, kext를 로드한 다음 memory를 dump할 수도 있습니다:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDB를 사용한 Live process dumping

**recent macOS versions**에서는 일반적으로 모든 physical memory를 image하려고 하기보다 **specific process**의 memory를 dump하는 것이 가장 실용적인 접근 방식입니다.

LLDB는 live target에서 Mach-O core file을 저장할 수 있습니다:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
기본적으로 이는 일반적으로 **skinny core**를 생성합니다. LLDB가 매핑된 프로세스 메모리를 모두 포함하도록 강제하려면:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
덤프 전에 유용한 후속 명령어:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
일반적으로 다음을 복구하려는 경우에는 이것으로 충분합니다:

- Decrypted configuration blobs
- 메모리에 있는 tokens, cookies 또는 credentials
- at rest 상태에서만 보호되는 plaintext secrets
- unpacking / JIT / runtime patching 이후 Decrypted Mach-O pages

대상이 **hardened runtime**으로 보호되거나 `taskgated`가 attach를 거부하는 경우에는 일반적으로 다음 조건 중 하나가 필요합니다:

- 대상에 **`get-task-allow`**가 포함되어 있음
- debugger가 적절한 **debugger entitlement**로 서명되어 있음
- 사용자가 **root**이고 대상이 non-hardened third-party process임

task port를 획득하는 방법과 이를 통해 수행할 수 있는 작업에 대한 자세한 내용은 다음을 참조하세요:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

LLDB/Frida에 시간을 들이기 전에 대상이 현실적으로 **dumpable**한지 빠르게 확인하세요:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
실무적으로는 보통 다음을 의미합니다.

- **`get-task-allow`**가 포함된 third-party app은 LLDB로 직접 dump할 수 있는 경우가 많으며, 생성된 dump에는 해당 app이 이미 접근한 TCC-protected data가 노출될 수 있습니다.<sup>[1]</sup>
- **hardened** target은 **`get-task-allow`**가 없으면 일반적으로 attach를 거부하며, `root`인 경우에도 관련 debugger entitlements / policy path를 제어하지 않는 한 마찬가지입니다.
- Unhardened third-party process는 여전히 `lldb`, `vmmap`, Frida 또는 custom `task_for_pid`/`vm_read` reader를 사용하기에 가장 쉬운 대상입니다.

### dump 가능한 nested helper 찾기

notarized macOS app을 대상으로 한 최근 research에서는 main GUI binary 대신 **nested helper**에서 **`get-task-allow`**가 발견되는 경우가 계속 보고되고 있습니다. 최상위 app이 hardened로 보이더라도 포기하기 전에 해당 app의 **XPC services**, **login items**, **helper tools**, 그리고 bundled CLIs를 열거하세요:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
`get-task-allow`가 설정된 내부 executable은 메인 앱이 더 강력하게 hardening되어 있더라도 `lldb`로 attach하거나, core를 dump하거나, custom `task_for_pid` client로 memory를 가져오기에 가장 쉬운 대상인 경우가 많습니다.

## Frida 또는 userland readers를 사용한 선택적 dump

전체 core가 너무 많은 noise를 포함하는 경우, **흥미로운 readable ranges**만 dump하는 것이 더 빠른 경우가 많습니다. Frida는 process에 attach할 수 있게 된 후 **targeted extraction**에 특히 유용합니다.

접근 방법 예시:

1. readable/writable ranges 열거
2. module, heap, stack 또는 anonymous memory 기준으로 필터링
3. candidate strings, keys, protobufs, plist/XML blobs 또는 decrypted code/data가 포함된 region만 dump

모든 readable anonymous ranges를 dump하는 최소 Frida 예시:
```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
try {
if (range.file) return;
var dump = range.base.readByteArray(range.size);
var f = new File('/tmp/' + range.base + '.bin', 'wb');
f.write(dump);
f.close();
} catch (e) {}
});
```
이 방법은 거대한 core 파일을 생성하지 않고 다음 항목만 수집하려는 경우에 유용합니다.

- secrets가 포함된 App heap chunks
- custom packer 또는 loader가 생성한 Anonymous regions
- protections를 변경한 후의 JIT / unpacked code pages

대상을 dump하는 동안에도 계속 **allocating / freeing**하는 경우, 불안정한 range에는 `readByteArray()`보다 Frida의 **`readVolatile()`** primitive를 사용하는 것이 좋습니다. 속도는 느리지만, 읽는 도중 page를 읽을 수 없게 되더라도 target이 종료되는 것을 방지합니다. 더 큰 acquisition의 경우, target 내부에 수천 개의 작은 파일을 생성하는 대신 `send(..., data)`를 사용해 chunks를 stream하고 controller 측에서 compress하는 편이 더 깔끔할 수 있습니다.

[`readmem`](https://github.com/gdbinit/readmem)과 같은 오래된 userland tools도 있지만, 주로 직접적인 `task_for_pid`/`vm_read` 방식의 dumping을 위한 **source references**로 유용하며, 최신 Apple Silicon workflows에서는 유지 관리가 잘 되지 않습니다.

## `.memgraph`를 사용한 Heap / VM snapshots

주로 **heap objects**, **allocation provenance** 또는 다른 machine으로 옮길 수 있는 snapshot에 관심이 있다면, `.memgraph`는 거대한 Mach-O core보다 더 실용적인 경우가 많습니다. `leaks` tooling을 사용하면 live process에서 이를 생성할 수 있습니다:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
그런 다음 표준 Apple 도구를 사용해 오프라인에서 이를 triage합니다:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups`는 `-fullContent` capture를 보관해야 하는 가장 큰 이유입니다. 최소 `.memgraph`에서는 memory contents를 설명하는 labels가 생략되기 때문입니다.

다음과 같은 경우에 특히 유용합니다.

- full core 대신 **더 작고 공유 가능한 snapshot**이 필요한 경우
- `MallocStackLogging`이 활성화되어 있고 **allocation backtraces**가 필요한 경우
- 이미 **흥미로운 heap address**를 알고 있으며 `malloc_history`로 pivot하려는 경우
- full dump가 남길 noise를 감수할 가치가 있는지 결정하기 전에 빠르게 **VM/heap breakdown**이 필요한 경우

### Differential memgraph triage

target이 시작되는 방식을 제어할 수 있다면, launch 전에 **historical allocation logging**을 활성화하여 이후 snapshot에서 유용한 alloc/free backtraces가 보존되도록 합니다.
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
그런 다음 관심 있는 작업 전후의 스냅샷을 캡처하고 오프라인에서 diff하세요:
```bash
# Baseline before login / decrypt / unpack
leaks <pid> -outputGraph /tmp/pre.memgraph -fullContent -fullStackHistory

# Snapshot after the sensitive action
leaks <pid> -outputGraph /tmp/post.memgraph -fullContent -fullStackHistory

# Show only new leaks introduced after the baseline
leaks /tmp/post.memgraph -diffFrom=/tmp/pre.memgraph

# Walk from roots to one candidate allocation, or filter the whole tree by class / VM type
leaks /tmp/post.memgraph -traceTree 0xADDR
leaks /tmp/post.memgraph -referenceTree='CFData[50k+]'

# Pivot into the preserved stack history at the interesting high-water mark
malloc_history /tmp/post.memgraph -callTree -highWaterMark
```
이는 **post-authentication objects**, **large `CFData` buffers** 또는 복호화, unpacking, secret-retrieval 단계 이후에만 나타나는 **anonymous VM regions**을 분리하는 실용적인 방법입니다.

## Swift-heavy targets: `swift-inspect`

높은 가치의 데이터를 **Swift runtime objects** 내부에 보관하는 애플리케이션의 경우, `swift-inspect`는 LLDB 또는 Frida를 보완하는 유용한 도구가 될 수 있습니다. 먼저 모든 것을 dump하는 대신, 실행 중인 프로세스에서 특정 Swift runtime structures를 조회할 수 있습니다:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
이 기능은 다음 항목을 식별하는 데 유용합니다.

- 흥미로운 데이터를 버퍼링하는 대형 Swift 배열
- 런타임에 로드된 타입을 드러내는 메타데이터 할당
- 더 정밀한 dump를 수행하기 전 Swift concurrency 상태(`Task`, actor, 스레드 관계)

프로세스를 이미 검사할 수 있는 경우, 객체 수준의 런타임 트리아지를 추가로 수행하려면 [메모리 내 객체 전용 페이지](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)를 확인하세요.

## 빠른 트리아지 참고 사항

- `sysctl vm.swapusage`는 여전히 **스왑 사용량**과 스왑이 **암호화되었는지** 확인하는 빠른 방법입니다.
- `sleepimage`는 주로 **hibernate/safe sleep** 시나리오에서 여전히 관련성이 있지만, 최신 시스템에서는 일반적으로 이를 보호하므로 신뢰할 수 있는 획득 경로가 아니라 **확인할 아티팩트 소스**로 취급해야 합니다.
- 최신 macOS 릴리스에서는 부팅 정책, SIP 상태 및 kext 로딩을 제어하지 않는 한 **전체 물리 메모리 이미징**보다 **프로세스 수준 dumping**이 일반적으로 더 현실적입니다.

## 참고 자료

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
