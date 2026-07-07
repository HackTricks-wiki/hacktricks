# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap files, such as `/private/var/vm/swapfile0`,는 **physical memory가 가득 찼을 때 cache 역할**을 한다. physical memory에 더 이상 공간이 없으면, 그 데이터는 swap file로 옮겨지고 필요할 때 다시 physical memory로 가져온다. swapfile0, swapfile1 같은 이름을 가진 여러 swap file이 존재할 수 있다.

### Hibernate Image

`/private/var/vm/sleepimage`에 있는 파일은 **hibernation mode**에서 매우 중요하다. **OS X가 hibernates할 때 memory의 데이터가 이 파일에 저장된다**. 컴퓨터를 깨우면 시스템은 이 파일에서 memory 데이터를 가져와 사용자가 중단했던 지점부터 계속할 수 있게 한다.

주의할 점은 최신 MacOS 시스템에서는 보안상의 이유로 이 파일이 보통 encrypted 되어 있어 복구가 어렵다는 것이다.

- sleepimage의 encryption이 활성화되어 있는지 확인하려면 `sysctl vm.swapusage` 명령을 실행할 수 있다. 그러면 해당 파일이 encrypted인지 확인할 수 있다.

### Memory Pressure Logs

MacOS 시스템에서 또 다른 중요한 memory 관련 파일은 **memory pressure log**이다. 이 로그는 `/var/log`에 위치하며 시스템의 memory 사용량과 pressure 이벤트에 대한 상세 정보를 담고 있다. 특히 memory 관련 문제를 진단하거나 시스템이 시간이 지나면서 memory를 어떻게 관리하는지 이해하는 데 유용하다.

## Dumping memory with osxpmem

MacOS machine에서 memory를 dump하려면 [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)을 사용할 수 있다.

**Note**: 이 방식은 현재 대부분 **legacy workflow**이다. `osxpmem`은 kernel extension 로딩에 의존하고, [Rekall](https://github.com/google/rekall) 프로젝트는 archived 되었으며, 최신 release는 **2017**년이고, 제공되는 binary는 **Intel Macs**를 대상으로 한다. 현재 macOS release, 특히 **Apple Silicon**에서는 kext 기반 full-RAM acquisition이 현대적인 kernel-extension 제한, SIP, platform-signing 요구사항 때문에 보통 차단된다. 실제로는 현대 시스템에서 전체 RAM image 대신 **process-scoped dump**를 하게 되는 경우가 더 많다.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
이 오류가 표시되면: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 다음과 같이 해결할 수 있습니다:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Other errors**는 "Security & Privacy --> General"에서 **kext의 로드를 허용**하면 해결될 수 있습니다. 그냥 **허용**하세요.

다음 **oneliner**를 사용해서 애플리케이션을 다운로드하고, kext를 로드한 뒤 메모리를 덤프할 수도 있습니다:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDB를 이용한 실행 중 프로세스 덤핑

**최근 macOS 버전**에서는 일반적으로 모든 물리 메모리를 이미지로 뜨려고 하기보다 **특정 프로세스**의 메모리를 덤프하는 것이 가장 실용적인 방법입니다.

LLDB는 실행 중인 대상에서 Mach-O core file을 저장할 수 있습니다:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
기본적으로 이것은 보통 **skinny core**를 생성합니다. LLDB가 매핑된 모든 프로세스 메모리를 포함하도록 강제하려면:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
덤프하기 전에 유용한 후속 명령:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
이는 일반적으로 다음을 복구하는 것이 목표일 때 충분합니다:

- Decrypted configuration blobs
- In-memory tokens, cookies, or credentials
- 평문으로 저장된 비밀값, 즉 at rest 상태에서만 보호되는 것들
- unpacking / JIT / runtime patching 후의 Decrypted Mach-O pages

대상이 **hardened runtime**으로 보호되거나, `taskgated`가 attach를 거부하는 경우에는 보통 다음 조건 중 하나가 필요합니다:

- 대상에 **`get-task-allow`**가 포함되어 있음
- 디버거가 올바른 **debugger entitlement**로 서명되어 있음
- 당신이 **root**이고 대상이 hardened가 아닌 서드파티 프로세스임

task port를 얻는 방법과 이를 통해 무엇을 할 수 있는지에 대한 추가 배경은 다음을 참고하세요:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

LLDB/Frida에 시간을 쓰기 전에, 대상이 현실적으로 **dumpable**인지 빠르게 확인하세요:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
운영상으로, 이는 보통 다음을 의미합니다:

- **`get-task-allow`**가 포함된 서드파티 앱은 LLDB로 직접 dump 가능한 경우가 많고, 그 결과 dump에는 앱이 이미 접근한 TCC 보호 데이터가 노출될 수 있습니다.
- `get-task-allow`가 없는 **hardened** 대상은, 관련 debugger entitlements / policy path를 제어하지 않는 한, 심지어 `root`로도 attach를 일반적으로 거부합니다.
- hardening이 적용되지 않은 서드파티 프로세스는 여전히 `lldb`, `vmmap`, Frida, 또는 커스텀 `task_for_pid`/`vm_read` reader를 사용하기 가장 쉬운 대상입니다.

## Frida 또는 userland reader를 사용한 선택적 dumps

전체 core가 너무 noisy할 때는, **흥미로운 readable range**만 dump하는 것이 종종 더 빠릅니다. Frida는 프로세스에 attach할 수만 있다면 **targeted extraction**에 특히 유용합니다.

예시 접근 방식:

1. readable/writable range 열거
2. module, heap, stack, 또는 anonymous memory 기준으로 필터링
3. candidate strings, keys, protobufs, plist/XML blobs, 또는 decrypted code/data를 포함하는 region만 dump

모든 readable anonymous range를 dump하는 최소 Frida 예제:
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
이는 거대한 core file을 피하고 다음만 수집하고 싶을 때 유용합니다:

- secrets를 포함한 App heap chunks
- custom packers 또는 loaders에 의해 생성된 anonymous regions
- protection 변경 후의 JIT / unpacked code pages

[`readmem`](https://github.com/gdbinit/readmem) 같은 오래된 userland tools도 존재하지만, 주로 직접적인 `task_for_pid`/`vm_read` 방식의 dumping을 위한 **source references**로만 유용하며, 최신 Apple Silicon workflow에는 잘 유지보수되지 않습니다.

## Heap / VM snapshots with `.memgraph`

주로 **heap objects**, **allocation provenance**, 또는 다른 machine으로 옮길 수 있는 snapshot에 관심이 있다면, `.memgraph`는 거대한 Mach-O core보다 종종 더 실용적입니다. `leaks` tooling은 live process에서 이를 생성할 수 있습니다:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
그런 다음 표준 Apple tooling으로 오프라인에서 triage it:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups`는 `-fullContent` 캡처를 유지해야 하는 주된 이유입니다. 메모리 내용에 대한 라벨이 최소 `.memgraph`에서는 생략되기 때문입니다.

이는 특히 다음과 같은 경우에 유용합니다:

- 전체 core 대신 **더 작고 공유하기 쉬운 스냅샷**이 필요할 때
- `MallocStackLogging`이 활성화되어 있고 **allocation backtraces**가 필요할 때
- 이미 **흥미로운 heap 주소**를 알고 있고 `malloc_history`로 pivot하고 싶을 때
- 전체 dump가 잡음 대비 가치가 있는지 결정하기 전에 빠른 **VM/heap breakdown**이 필요할 때

## Swift-heavy targets: `swift-inspect`

고가치 데이터를 **Swift runtime objects** 안에 저장하는 애플리케이션의 경우, `swift-inspect`는 LLDB나 Frida를 보완하는 좋은 도구가 될 수 있습니다. 먼저 전부 dump하는 대신, live process에서 특정 Swift runtime structures를 질의할 수 있습니다:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
This is handy to identify:

- Large Swift arrays buffering interesting data
- Metadata allocations that reveal types loaded at runtime
- Swift concurrency state (`Task`, actor, thread relationships) before doing a more targeted dump

For more object-level runtime triage once you can already inspect the process, check [the dedicated page on objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Quick triage notes

- `sysctl vm.swapusage` is still a quick way to check **swap usage** and whether swap is **encrypted**.
- `sleepimage` remains relevant mainly for **hibernate/safe sleep** scenarios, but modern systems commonly protect it, so it should be treated as an **artifact source to check**, not as a reliable acquisition path.
- On recent macOS releases, **process-level dumping** is generally more realistic than **full physical memory imaging** unless you control boot policy, SIP state, and kext loading.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
