# macOS 메모리 덤프

{{#include ../../../banners/hacktricks-training.md}}

## 메모리 아티팩트

### Swap 파일

`/private/var/vm/swapfile0`과 같은 Swap 파일은 **물리 메모리가 가득 찼을 때 캐시 역할**을 합니다. 물리 메모리에 더 이상 공간이 없으면 해당 데이터가 Swap 파일로 전송된 후, 필요에 따라 물리 메모리로 다시 가져옵니다. swapfile0, swapfile1 등과 같은 이름의 Swap 파일이 여러 개 존재할 수 있습니다.

### Hibernate 이미지

`/private/var/vm/sleepimage`에 위치한 파일은 **최대 절전 모드**에서 중요합니다. **OS X가 최대 절전 모드로 전환될 때 메모리의 데이터가 이 파일에 저장**됩니다. 컴퓨터를 다시 깨우면 시스템은 이 파일에서 메모리 데이터를 가져와 사용자가 중단했던 지점부터 계속할 수 있도록 합니다.

최신 MacOS 시스템에서는 보안상의 이유로 이 파일이 일반적으로 암호화되어 있으므로 복구가 어렵다는 점에 유의해야 합니다.

- sleepimage의 암호화 활성화 여부를 확인하려면 `sysctl vm.swapusage` 명령을 실행할 수 있습니다. 이 명령은 파일이 암호화되었는지 보여줍니다.

### 메모리 압력 로그

MacOS 시스템에서 메모리와 관련된 또 다른 중요한 파일은 **메모리 압력 로그**입니다. 이러한 로그는 `/var/log`에 위치하며 시스템의 메모리 사용량과 압력 이벤트에 대한 자세한 정보를 포함합니다. 메모리 관련 문제를 진단하거나 시스템이 시간에 따라 메모리를 어떻게 관리하는지 파악하는 데 특히 유용할 수 있습니다.

## osxpmem을 사용한 메모리 덤프

MacOS 시스템에서 메모리를 덤프하려면 [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)을 사용할 수 있습니다.

**참고**: 현재는 대부분 **legacy workflow**입니다. `osxpmem`은 kernel extension을 로드해야 하고, [Rekall](https://github.com/google/rekall) 프로젝트는 아카이브되었으며, 최신 release는 **2017년**에 나왔고, 공개된 binary는 **Intel Mac**을 대상으로 합니다. 최신 macOS release, 특히 **Apple Silicon**에서는 kext 기반의 전체 RAM 수집이 일반적으로 최신 kernel extension 제한, SIP 및 platform-signing 요구 사항으로 차단됩니다. 실제로 최신 시스템에서는 전체 RAM image 대신 **process-scoped dump**를 수행하게 되는 경우가 더 많습니다.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
다음 오류가 발생하면: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 다음을 수행하여 해결할 수 있습니다:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**기타 오류**는 "Security & Privacy --> General"에서 **kext 로드를 허용**하면 해결될 수 있습니다. 그냥 **허용**하세요.

다음 **oneliner**를 사용하여 애플리케이션을 다운로드하고, kext를 로드한 다음 메모리를 dump할 수도 있습니다:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDB를 사용한 실행 중인 프로세스 dumping

**최근 macOS 버전**에서는 일반적으로 모든 physical memory를 image하려 하기보다 **특정 프로세스**의 memory를 dumping하는 것이 가장 실용적인 접근 방식입니다.

LLDB는 실행 중인 target에서 Mach-O core file을 저장할 수 있습니다:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
기본적으로 이는 일반적으로 **skinny core**를 생성합니다. LLDB가 매핑된 프로세스 메모리를 모두 포함하도록 강제하려면:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
덤프하기 전에 유용한 후속 명령어:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
이 작업은 일반적으로 다음 항목을 복구하려는 경우에 충분합니다:

- Decrypted configuration blobs
- 메모리 내 tokens, cookies 또는 credentials
- 저장 시점에만 보호되는 Plaintext secrets
- unpacking / JIT / runtime patching 이후의 Decrypted Mach-O pages

대상이 **hardened runtime**으로 보호되거나 `taskgated`가 attach를 거부하는 경우에는 일반적으로 다음 조건 중 하나가 필요합니다:

- 대상에 **`get-task-allow`**가 포함되어 있음
- 디버거가 적절한 **debugger entitlement**로 서명되어 있음
- 사용자가 **root**이고 대상이 non-hardened third-party process임

task port를 얻는 방법과 이를 통해 수행할 수 있는 작업에 대한 자세한 내용은 다음을 참조하세요:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### 빠른 attach 전 검사

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

- **`get-task-allow`**가 포함된 third-party app은 LLDB를 사용해 직접 dump할 수 있는 경우가 많으며, 그 결과로 생성된 dump에는 해당 app이 이미 액세스한 TCC-protected data가 노출될 수 있습니다.<sup>[[1]](#references)</sup>
- **hardened** target은 `get-task-allow`가 없으면 일반적으로 attach를 거부하며, 관련 debugger entitlements 또는 policy path를 제어하지 않는 한 `root` 권한으로도 마찬가지입니다.
- Unhardened third-party process는 여전히 `lldb`, `vmmap`, Frida 또는 custom `task_for_pid`/`vm_read` reader를 사용하기에 가장 쉬운 대상입니다.

### dump 가능한 nested helper 탐색

Notarized macOS app에 대한 최근 research에서는 main GUI binary가 아닌 **nested helper**에서 **`get-task-allow`**가 계속 발견되고 있습니다. 최상위 app이 hardened로 보이더라도 포기하기 전에 해당 app의 **XPC services**, **login items**, **helper tools**, bundled CLI를 열거하세요:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
`get-task-allow`가 적용된 중첩 실행 파일은 main app이 더 강력하게 hardening되어 있더라도 `lldb`로 attach하거나 core를 dump하거나 custom `task_for_pid` client로 memory를 가져올 수 있는 가장 쉬운 지점인 경우가 많습니다.

## Frida 또는 userland readers를 사용한 선택적 dump

전체 core가 너무 noisy한 경우에는 **흥미로운 readable ranges만** dump하는 것이 더 빠른 경우가 많습니다. Frida는 process에 attach할 수 있게 된 후 **targeted extraction**을 수행하는 데 특히 유용합니다.

접근 방법 예시:

1. readable/writable ranges 열거
2. module, heap, stack 또는 anonymous memory를 기준으로 필터링
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
이는 거대한 core 파일을 피하고 다음 항목만 수집하려는 경우에 유용합니다:

- secrets를 포함하는 App heap chunks
- custom packers 또는 loaders가 생성한 Anonymous regions
- protections 변경 후의 JIT / unpacked code pages

대상을 dump하는 동안 계속 **allocating / freeing**하는 경우, 불안정한 range에는 `readByteArray()`보다 Frida의 **`readVolatile()`** primitive를 사용하는 것이 좋습니다. 속도는 느리지만, 읽는 도중 page를 읽을 수 없게 되더라도 target이 종료되는 것을 방지합니다. 더 큰 acquisition의 경우, `send(..., data)`를 사용해 chunks를 다시 stream하고 target 내부에 수천 개의 작은 파일을 생성하는 대신 controller 측에서 이를 compress하는 편이 더 깔끔할 수 있습니다.

[`readmem`](https://github.com/gdbinit/readmem)과 같은 오래된 userland tools도 존재하지만, 주로 직접적인 `task_for_pid`/`vm_read` 방식의 dumping을 위한 **source references**로 유용하며 modern Apple Silicon workflows에서는 유지 관리가 잘 되지 않습니다.

## `.memgraph`를 사용한 Heap / VM snapshots

주로 **heap objects**, **allocation provenance** 또는 다른 machine으로 이동할 수 있는 snapshot에 관심이 있다면, `.memgraph`는 거대한 Mach-O core보다 더 실용적인 경우가 많습니다. `leaks` tooling을 사용하면 live process에서 이를 생성할 수 있습니다:
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
`stringdups`는 `-fullContent` capture를 보관해야 하는 주된 이유입니다. 최소 `.memgraph`에서는 memory contents를 설명하는 label이 생략되기 때문입니다.

다음과 같은 경우에 특히 유용합니다.

- 전체 core 대신 **더 작고 공유 가능한 snapshot**이 필요한 경우
- `MallocStackLogging`이 활성화되어 있고 **allocation backtrace**가 필요한 경우
- 이미 **흥미로운 heap address**를 알고 있으며 `malloc_history`로 pivot하려는 경우
- full dump를 생성할 가치가 있는지 결정하기 전에 빠르게 **VM/heap breakdown**이 필요한 경우

### Differential memgraph triage

target의 시작 방식을 제어할 수 있다면, launch 전에 **historical allocation logging**을 활성화하여 이후 snapshot에 유용한 alloc/free backtrace가 보존되도록 합니다.
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

중요한 데이터가 **Swift runtime objects** 내부에 저장되는 애플리케이션의 경우, `swift-inspect`는 LLDB 또는 Frida를 보완하는 유용한 도구가 될 수 있습니다. 먼저 모든 것을 dump하는 대신, 실행 중인 process에서 특정 Swift runtime structures를 query할 수 있습니다:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
이는 다음 항목을 식별하는 데 유용합니다.

- 흥미로운 데이터를 버퍼링하는 대규모 Swift 배열
- 런타임에 로드된 type을 드러내는 metadata 할당
- 보다 targeted한 dump를 수행하기 전의 Swift concurrency 상태(`Task`, actor, thread 관계)

이미 process를 inspect할 수 있는 경우, object-level runtime triage에 대해서는 [메모리 내 objects 전용 페이지](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)를 확인하세요.

## 빠른 triage 참고 사항

- `sysctl vm.swapusage`는 여전히 **swap usage**와 swap이 **encrypted**되어 있는지 확인하는 빠른 방법입니다.
- `sleepimage`는 주로 **hibernate/safe sleep** 시나리오에서 여전히 중요하지만, 최신 시스템에서는 일반적으로 보호되므로 신뢰할 수 있는 acquisition 경로가 아닌 **확인해야 할 artifact source**로 취급해야 합니다.
- 최신 macOS 릴리스에서는 boot policy, SIP 상태 및 kext loading을 제어하지 않는 한 **full physical memory imaging**보다 **process-level dumping**이 일반적으로 더 현실적입니다.

## References

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
