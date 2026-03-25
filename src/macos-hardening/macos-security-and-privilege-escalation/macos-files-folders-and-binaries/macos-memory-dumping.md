# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## 메모리 아티팩트

### 스왑 파일

Swap files, such as `/private/var/vm/swapfile0`, serve as **물리 메모리가 가득 찼을 때의 캐시**. 물리 메모리에 더 이상 여유가 없으면 데이터가 스왑 파일로 옮겨졌다가 필요할 때 다시 물리 메모리로 불러옵니다. swapfile0, swapfile1 등 여러 개의 스왑 파일이 존재할 수 있습니다.

### Hibernate Image

The file located at `/private/var/vm/sleepimage` is crucial during **hibernation mode**. **Data from memory is stored in this file when OS X hibernates**. Upon waking the computer, the system retrieves memory data from this file, allowing the user to continue where they left off.

현대의 MacOS 시스템에서는 보안상 이 파일이 일반적으로 암호화되어 있어 복구가 어렵다는 점에 유의해야 합니다.

- To check if encryption is enabled for the sleepimage, the command `sysctl vm.swapusage` can be run. This will show if the file is encrypted.

### 메모리 압력 로그

Another important memory-related file in MacOS systems is the **memory pressure log**. These logs are located in `/var/log` and contain detailed information about the system's memory usage and pressure events. They can be particularly useful for diagnosing memory-related issues or understanding how the system manages memory over time.

## Dumping memory with osxpmem

In order to dump the memory in a MacOS machine you can use [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: This is mostly a **legacy workflow** now. `osxpmem` depends on loading a kernel extension, the [Rekall](https://github.com/google/rekall) project is archived, the latest release is from **2017**, and the published binary targets **Intel Macs**. On current macOS releases, especially on **Apple Silicon**, kext-based full-RAM acquisition is usually blocked by modern kernel-extension restrictions, SIP, and platform-signing requirements. In practice, on modern systems you will more often end up doing a **process-scoped dump** instead of a whole-RAM image.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
다음 오류가 발생하면: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 다음과 같이 해결할 수 있습니다:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**다른 오류**는 "Security & Privacy --> General"에서 **kext 로드 허용**을 통해 해결될 수 있습니다. 단순히 **허용**하세요.

또는 이 **oneliner**를 사용하여 애플리케이션을 다운로드하고, kext를 로드하며 메모리를 덤프할 수 있습니다:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDB를 사용한 라이브 프로세스 덤핑

**최근 macOS 버전**에서는 전체 물리 메모리를 이미지화하려 시도하기보다는 **특정 프로세스**의 메모리를 덤프하는 것이 보통 가장 실용적인 방법입니다.

LLDB는 실행 중인 대상에서 Mach-O 코어 파일을 저장할 수 있습니다:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
기본적으로 이는 보통 **skinny core**를 생성합니다. LLDB가 매핑된 모든 프로세스 메모리를 포함하도록 강제하려면:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
dumping 전에 유용한 후속 명령:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
다음을 복구하려는 목적이라면 보통 이로 충분합니다:

- 복호화된 구성 블롭
- 메모리 내 토큰, 쿠키 또는 자격 증명
- 저장 시에만 보호되는 평문 비밀
- 언패킹 / JIT / 런타임 패칭 후 복호화된 Mach-O 페이지

타깃이 **hardened runtime**으로 보호되어 있거나 `taskgated`가 어태치를 거부하면, 일반적으로 다음 중 하나가 필요합니다:

- 타깃에 **`get-task-allow`**가 설정되어 있음
- 디버거가 적절한 **debugger entitlement**로 서명되어 있음
- 당신이 **root**이고 타깃이 비-hardened 서드파티 프로세스임

For more background on obtaining a task port and what can be done with it:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Frida 또는 userland readers를 이용한 선택적 덤프

전체 코어 덤프가 너무 노이즈가 많을 때, **흔히 흥미로운 읽기 가능한 영역(interesting readable ranges)**만 덤프하는 것이 더 빠릅니다. Frida는 프로세스에 어태치할 수 있으면 **targeted extraction**에 특히 유용합니다.

예시 절차:

1. 읽기/쓰기 가능한 범위를 열거
2. 모듈, 힙, 스택 또는 익명 메모리로 필터링
3. 후보 문자열, 키, protobufs, plist/XML 블롭, 또는 복호화된 코드/데이터를 포함하는 영역만 덤프

모든 읽기 가능한 익명 범위를 덤프하는 최소 Frida 예제:
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
이 방법은 거대한 코어 파일을 피하고 다음 항목만 수집하려는 경우에 유용합니다:

- App 힙 청크(비밀 포함)
- 커스텀 packers 또는 loaders가 생성한 익명 영역
- 보호 변경 후의 JIT / unpacked 코드 페이지

구형 userland 도구로 [`readmem`](https://github.com/gdbinit/readmem) 같은 것들도 존재하지만, 이들은 주로 직접적인 `task_for_pid`/`vm_read` 스타일 덤핑을 위한 **소스 참조**로 유용하며 최신 Apple Silicon 워크플로우에는 잘 유지되지 않습니다.

## 빠른 초기 점검

- `sysctl vm.swapusage` 는 여전히 **swap usage** 및 스왑이 **encrypted**인지 확인하는 빠른 방법입니다.
- `sleepimage` 는 주로 **hibernate/safe sleep** 시나리오에서 여전히 관련이 있지만, 최신 시스템은 일반적으로 이를 보호하므로 신뢰할 수 있는 획득 경로라기보다는 확인해야 할 **artifact source to check**로 취급해야 합니다.
- 최근 macOS 릴리스에서는 부트 정책, SIP 상태 및 kext 로딩을 제어하지 않는 한, **process-level dumping**이 일반적으로 **full physical memory imaging**보다 현실적입니다.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
