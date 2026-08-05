# macOS 앱 - Inspecting, debugging and Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Static Analysis

### otool & objdump & nm
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```

```bash
nm -m ./tccd # List of symbols
```
### Disarm (old jtool2)

[**여기에서 disarm을 다운로드할 수 있습니다**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> **`disarm`**은 압축된 IM4P 파일(`kernelcache` 등)에서도 작동하며, 필요한 부분만 추출하거나 추출하지 않고도 필요한 부분을 분석할 수 있습니다.
```bash
export JCOLOR=1
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled

disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache
JDEBUG=1 disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache with debug info
disarm -r "code signature" /bin/ps # Check code signature of a binary
disarm -e "code signature" /bin/ps # Extract code signature of a binary
```
### Codesign / ldid

> [!TIP]
> **`Codesign`**은 **macOS**에서 사용할 수 있으며, **`ldid`**는 **iOS**에서 사용할 수 있습니다.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html)는 **.pkg** 파일(installers)을 inspect하고 설치하기 전에 내부 내용을 확인하는 데 유용한 tool입니다.\
이러한 installers에는 malware authors가 **malware**를 **persist**하기 위해 일반적으로 abuse하는 `preinstall` 및 `postinstall` bash scripts가 포함되어 있습니다.

### hdiutil

이 tool을 사용하면 Apple disk images (**.dmg**) 파일을 **mount**하여 어떤 작업도 실행하기 전에 inspect할 수 있습니다:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
`/Volumes`에 마운트됩니다

### Packed binaries

- 높은 entropy를 확인
- strings를 확인 (이해 가능한 문자열이 거의 없다면 packed)
- MacOS용 UPX packer는 "\_\_XHDR"라는 section을 생성합니다

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> Objective-C로 작성된 프로그램은 [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)로 **컴파일**될 **때**에도 class declarations를 **유지**합니다. 이러한 class declarations에는 다음의 이름과 type이 **포함**됩니다:

- 정의된 interfaces
- interface methods
- interface instance variables
- 정의된 protocols

이러한 이름은 binary의 reversing을 더 어렵게 만들기 위해 obfuscate될 수 있습니다.

### Function calling

Objective-C를 사용하는 binary에서 function이 호출되면, compiled code는 해당 function을 직접 호출하는 대신 **`objc_msgSend`**를 호출합니다. 이 function이 최종 function을 호출합니다:

![Metadata - Function calling: Objective-C를 사용하는 binary에서 function이 호출되면, compiled code는 해당 function을 직접 호출하는 대신 objc msgSend를 호출합니다. 이 function이...](<../../../images/image (305).png>)

이 function이 예상하는 params는 다음과 같습니다:

- 첫 번째 parameter (**self**)는 "**message를 받을 class의 instance를 가리키는 pointer**"입니다. 더 간단히 말하면, method가 invoke되는 object입니다. method가 class method인 경우 이는 class object 전체의 instance가 되며, instance method인 경우 self는 class의 instantiated instance를 object로 가리킵니다.
- 두 번째 parameter인 (**op**)는 "message를 처리하는 method의 selector"입니다. 다시 간단히 말하면, 이는 **method의 name**입니다.
- 나머지 parameters는 method (op)에 필요한 **values**입니다.

이 페이지에서 **ARM64의 `lldb`로 이 정보를 쉽게 가져오는 방법**을 확인할 수 있습니다:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self: method가 invoke되는 object** |
| **2nd argument**  | **rsi**                                                         | **op: method의 name**                             |
| **3rd argument**  | **rdx**                                                         | **method의 1st argument**                         |
| **4th argument**  | **rcx**                                                         | **method의 2nd argument**                         |
| **5th argument**  | **r8**                                                          | **method의 3rd argument**                         |
| **6th argument**  | **r9**                                                          | **method의 4th argument**                         |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(on the stack)</strong></p> | **method의 5th+ argument**                        |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump)는 Objective-C binaries를 class-dump하는 tool입니다. github에는 dylibs라고 명시되어 있지만 executables에서도 작동합니다.
```bash
./dynadump dump /path/to/bin
```
작성 시점에는 **현재 이것이 가장 잘 작동합니다**.

#### 일반 도구
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/)는 Objective-C 형식의 코드에 포함된 클래스, 카테고리 및 프로토콜에 대한 선언을 생성하는 최초의 도구입니다.

오래되었고 유지 관리되지 않으므로 제대로 작동하지 않을 가능성이 높습니다.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump)는 최신의 cross-platform Objective-C class dump 도구입니다. 기존 도구와 비교해 iCDump는 Apple 생태계와 독립적으로 실행할 수 있으며 Python bindings를 제공합니다.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Static Swift 분석

Swift binary에는 Objective-C compatibility가 있으므로, 경우에 따라 [class-dump](https://github.com/nygard/class-dump/)를 사용해 declarations를 추출할 수 있지만 항상 가능한 것은 아닙니다.

**`jtool -l`** 또는 **`otool -l`** command line을 사용하면 **`__swift5`** prefix로 시작하는 여러 sections를 찾을 수 있습니다:
```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
[...]
Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
[...]
```
이러한 section에 저장된 **information에 대한 자세한 내용은 이 [**blog post**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)에서 확인할 수 있습니다**.

또한 **Swift binaries에는 symbols가 포함되어 있을 수 있습니다**(예를 들어 libraries는 해당 functions를 호출할 수 있도록 symbols를 저장해야 합니다). **symbols에는 일반적으로 function name과 attr 정보가 보기 좋지 않은 방식으로 포함**되어 있으므로 매우 유용하며, 원래 이름을 가져올 수 있는 "**demanglers"**가 있습니다:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dynamic Analysis

> [!WARNING]
> 바이너리를 debug하려면 **SIP를 비활성화**해야 합니다(`csrutil disable` 또는 `csrutil enable --without debug`). 또는 바이너리를 임시 폴더에 복사한 후 `codesign --remove-signature <binary-path>`를 사용해 **signature를 제거**하거나 바이너리의 debugging을 허용해야 합니다([이 script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)를 사용할 수 있습니다).

> [!WARNING]
> macOS에서 `cloudconfigurationd`와 같은 **system binaries를 instrument**하려면 **SIP를 비활성화해야** 합니다(signature만 제거하는 것으로는 작동하지 않습니다).

### APIs

macOS는 process에 대한 정보를 제공하는 몇 가지 흥미로운 APIs를 노출합니다.

- `proc_info`: 각 process에 대한 많은 정보를 제공하는 주요 API입니다. 다른 process의 정보를 가져오려면 root 권한이 필요하지만, special entitlements나 mach ports는 필요하지 않습니다.
- `libsysmon.dylib`: XPC로 노출된 functions를 통해 process 정보를 가져올 수 있지만, `com.apple.sysmond.client` entitlement가 필요합니다.

### Stackshot & microstackshots

**Stackshotting**은 실행 중인 모든 thread의 call stacks를 포함해 process의 상태를 캡처하는 데 사용하는 technique입니다. 이는 특정 시점의 system을 debug하고, performance를 분석하며, 동작을 이해하는 데 특히 유용합니다. iOS와 macOS에서는 **`sample`** 및 **`spindump`**와 같은 여러 tools와 methods를 사용해 stackshotting을 수행할 수 있습니다.

### Sysdiagnose

이 tool(` /usr/bini/ysdiagnose`)은 기본적으로 `ps`, `zprint` 등 수십 가지 command를 실행해 computer에서 많은 정보를 수집합니다.

이는 **root**로 실행해야 하며, daemon `/usr/libexec/sysdiagnosed`에는 `com.apple.system-task-ports`와 `get-task-allow` 같은 매우 흥미로운 entitlements가 있습니다.

해당 plist는 `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`에 있으며, 다음 3개의 MachServices를 선언합니다.

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp의 이전 archives를 삭제합니다.
- `com.apple.sysdiagnose.kernel.ipc`: Special port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C class를 통한 user mode interface입니다. dict에 3개의 arguments(`compress`, `display`, `run`)를 전달할 수 있습니다.

### Unified Logs

MacOS는 application을 실행하면서 **무엇을 하고 있는지** 파악할 때 매우 유용한 많은 logs를 생성합니다.

또한 일부 logs에는 **user** 또는 **computer**의 **식별 가능한** 정보를 **숨기기** 위해 `<private>` tag가 포함됩니다. 하지만 **certificate를 설치해 이 정보를 공개**할 수 있습니다. 자세한 설명은 [**여기**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)를 참조하세요.

### Hopper

#### Left panel

Hopper의 left panel에서는 binary의 symbols(**Labels**), procedures와 functions 목록(**Proc**), strings(**Str**)을 확인할 수 있습니다. 이는 모든 strings가 아니라 Mac-O file의 여러 부분(예: _cstring 또는 `objc_methname`)에 정의된 strings입니다.

#### Middle panel

middle panel에서는 **disassembled code**를 확인할 수 있습니다. 또한 각 아이콘을 클릭해 이를 **raw** disassemble, **graph**, **decompiled**, **binary** 형식으로 확인할 수 있습니다.

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

code object를 right-click하면 해당 object의 **references to/from**를 확인하거나 이름을 변경할 수 있습니다(이는 decompiled pseudocode에서는 작동하지 않습니다).

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

또한 **middle panel 하단에서는 Python commands를 작성**할 수 있습니다.

#### Right panel

right panel에서는 **navigation history**(현재 상태에 어떻게 도달했는지 확인할 수 있음), 모든 **이 function을 호출하는 functions**와 **이 function이 호출하는 모든 functions**를 확인할 수 있는 **call grap**h, 그리고 **local variables** 정보와 같은 흥미로운 정보를 확인할 수 있습니다.

### dtrace

사용자가 application에 매우 **low level**로 접근할 수 있게 하며, **programs를 trace**하고 execution flow를 변경할 수 있는 방법을 제공합니다. Dtrace는 **probes**를 사용하며, 이 probes는 **kernel 전반에 배치**되어 system calls의 시작과 종료 지점 같은 위치에 존재합니다.

DTrace는 각 system call에 대한 probe를 생성하기 위해 **`dtrace_probe_create`** function을 사용합니다. 이 probes는 각 system call의 **entry 및 exit point**에서 실행될 수 있습니다. DTrace와의 interaction은 root user만 사용할 수 있는 `/dev/dtrace`를 통해 이루어집니다.

> [!TIP]
> SIP protection을 완전히 비활성화하지 않고 Dtrace를 활성화하려면 recovery mode에서 다음을 실행할 수 있습니다: `csrutil enable --without dtrace`
>
> 직접 **compile한** **`dtrace`** 또는 **`dtruss`** binaries도 사용할 수 있습니다.

dtrace에서 사용 가능한 probes는 다음과 같이 확인할 수 있습니다.
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
probe name은 provider, module, function, name의 네 부분으로 구성됩니다(`fbt:mach_kernel:ptrace:entry`). name의 일부를 지정하지 않으면 DTrace는 해당 부분을 wildcard로 적용합니다.

DTrace가 probe를 활성화하고 probe가 실행될 때 수행할 action을 지정하도록 구성하려면 D language를 사용해야 합니다.

더 자세한 설명과 추가 examples는 [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)에서 확인할 수 있습니다.

#### Examples

**DTrace scripts available**를 나열하려면 `man -k dtrace`를 실행합니다. Example: `sudo dtruss -n binary`

- 라인에서
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
- script
```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
;
}
syscall:::return
{
printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```
### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### kdebug

커널 tracing facility입니다. 문서화된 코드는 **`/usr/share/misc/trace.codes`**에서 확인할 수 있습니다.

`latency`, `sc_usage`, `fs_usage` 및 `trace`와 같은 도구는 내부적으로 이를 사용합니다.

`kdebug`와 인터페이스하기 위해 `sysctl`은 `kern.kdebug` namespace를 통해 사용되며, 사용할 MIB는 `sys/sysctl.h`에서 확인할 수 있고 함수는 `bsd/kern/kdebug.c`에 구현되어 있습니다.

custom client로 kdebug와 상호작용할 때 일반적인 단계는 다음과 같습니다.

- KERN_KDSETREMOVE를 사용하여 기존 설정 제거
- KERN_KDSETBUF 및 KERN_KDSETUP을 사용하여 trace 설정
- KERN_KDGETBUF를 사용하여 buffer entries 수 확인
- KERN_KDPINDEX를 사용하여 trace에서 자체 client 제외
- KERN_KDENABLE을 사용하여 tracing 활성화
- KERN_KDREADTR을 호출하여 buffer 읽기
- KERN_KDTHRMAP을 사용하여 각 thread를 해당 process와 매칭

이 정보를 얻으려면 Apple 도구인 **`trace`** 또는 custom tool인 [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**를 사용할 수 있습니다.**

**Kdebug는 한 번에 1명의 사용자만 사용할 수 있다는 점에 유의하세요.** 따라서 k-debug 기반 도구는 한 번에 하나만 실행할 수 있습니다.

### ktrace

`ktrace_*` APIs는 `libktrace.dylib`에서 제공되며, `Kdebug`의 API를 wrapping합니다. 따라서 client는 `ktrace_session_create`와 `ktrace_events_[single/class]`를 호출하여 특정 코드에 callback을 설정한 다음 `ktrace_start`로 시작할 수 있습니다.

**SIP가 활성화된 상태에서도** 사용할 수 있습니다.

client로 다음 utility를 사용할 수 있습니다: `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
또는 `tailspin`.

### kperf

이는 kernel level profiling을 수행하는 데 사용되며 `Kdebug` callout을 사용해 빌드되었습니다.

기본적으로 전역 변수 `kernel_debug_active`가 확인되고, 해당 변수가 설정되어 있으면 `Kdebug` code와 호출 중인 kernel frame의 address를 사용해 `kperf_kdebug_handler`를 호출합니다. `Kdebug` code가 선택된 code 중 하나와 일치하면 bitmap으로 구성된 "actions"를 가져옵니다(옵션은 `osfmk/kperf/action.h`를 확인하세요).

Kperf에는 sysctl MIB table도 있습니다: (root 권한으로) `sysctl kperf`. 이러한 code는 `osfmk/kperf/kperfbsd.c`에서 확인할 수 있습니다.

또한 Kperf functionality의 일부는 `kpc`에 있으며, 이는 machine performance counter에 대한 정보를 제공합니다.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor)는 process가 수행하는 process 관련 actions를 확인하는 데 매우 유용한 tool입니다(예: process가 생성하는 새로운 process를 모니터링).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/)는 process 간의 관계를 출력하는 tool입니다.\
먼저 **`sudo eslogger fork exec rename create > cap.json`**과 같은 command로 Mac을 모니터링해야 합니다(이를 실행하는 terminal에는 FDA가 필요합니다). 그런 다음 이 tool에서 json을 load하여 모든 관계를 확인할 수 있습니다:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor)는 file event(예: creation, modification, deletion)를 모니터링하고 이러한 event에 대한 자세한 정보를 제공합니다.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo)는 Windows 사용자가 Microsoft Sysinternal의 _Procmon_에서 알고 있을 법한 look and feel을 제공하는 GUI tool입니다. 이 tool을 사용하면 다양한 event type의 recording을 시작하고 중지할 수 있으며, file, process, network 등의 category별로 이러한 event를 filter할 수 있고, 기록된 event를 json format으로 저장할 수 있습니다.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html)는 Xcode Developer tools의 일부로, application performance 모니터링, memory leak 식별 및 filesystem activity 추적에 사용됩니다.

![Crescendo - Apple Instruments: Apple Instruments는 Xcode Developer tools의 일부로, application performance 모니터링, memory leak 식별 및 filesystem activity 추적에 사용됩니다](<../../../images/image (1138).png>)

### fs_usage

process가 수행하는 actions를 추적할 수 있습니다:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html)은 binary가 사용하는 **libraries**, 사용하는 **files**, 그리고 **network** connections를 확인하는 데 유용합니다.\
또한 binary processes를 **virustotal**과 대조하고 binary에 대한 정보를 표시합니다.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**이 blog post**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)에서 SIP가 비활성화된 경우에도 **`PT_DENY_ATTACH`**를 사용해 debugging을 방지하는 **running daemon을 debug**하는 방법의 예제를 확인할 수 있습니다.

### lldb

**lldb**는 macOS binary **debugging**을 위한 사실상의 **tool**입니다.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
홈 폴더에 다음 줄이 포함된 **`.lldbinit`** 파일을 생성하여 lldb를 사용할 때 intel flavour를 설정할 수 있습니다:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> lldb 내부에서 `process save-core`를 사용하여 프로세스를 dump합니다.

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Command</strong></td><td><strong>설명</strong></td></tr><tr><td><strong>run (r)</strong></td><td>실행을 시작하며, breakpoint에 도달하거나 프로세스가 종료될 때까지 중단 없이 계속 실행됩니다.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>entry point에서 실행을 중지한 상태로 실행을 시작합니다.</td></tr><tr><td><strong>continue (c)</strong></td><td>debug 중인 프로세스의 실행을 계속합니다.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>다음 instruction을 실행합니다. 이 command는 function call을 건너뜁니다.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>다음 instruction을 실행합니다. nexti command와 달리 이 command는 function call 내부로 step합니다.</td></tr><tr><td><strong>finish (f)</strong></td><td>현재 function(“frame”)의 나머지 instruction을 실행하고 return한 뒤 중지합니다.</td></tr><tr><td><strong>control + c</strong></td><td>실행을 일시 중지합니다. 프로세스가 run (r) 또는 continue (c)된 상태라면, 현재 실행 중인 위치에서 프로세스를 중지합니다.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Any func called main</p><p><code>b <binname>`main</code> #Main func of the bin</p><p><code>b set -n main --shlib <lib_name></code> #Main func of the indicated bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Any NSFileManager method</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint list</p><p><code>br e/dis <num></code> #Enable/Disable breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>memory를 null-terminated string으로 표시합니다.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>memory를 assembly instruction으로 표시합니다.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>memory를 byte로 표시합니다.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>param이 참조하는 object를 출력합니다.</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Apple의 Objective-C API 또는 method 대부분은 object를 return하므로 “print object”(po) command를 사용해 표시해야 합니다. po가 의미 있는 output을 생성하지 않으면 <code>x/b</code>를 사용합니다.</p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n <funcname> #Disas func</p><p>dis -n <funcname> -b <basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>현재 프로세스 memory의 map을 출력합니다.</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Get the address of all the symbols from CoreNLP</td></tr></tbody></table>

> [!TIP]
> **`objc_sendMsg`** function을 호출할 때 **rsi** register에는 null-terminated(“C”) string 형태의 **method 이름**이 저장됩니다. lldb를 사용하여 이름을 출력하려면 다음을 실행합니다.
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- **`sysctl hw.model`** command는 **host가 MacOS**일 때 "Mac"을 반환하지만, VM에서는 다른 값을 반환합니다.
- 일부 malware는 **`hw.logicalcpu`** 및 **`hw.physicalcpu`** 값을 조작하여 VM인지 탐지하려고 합니다.
- 일부 malware는 MAC address(00:50:56)를 기준으로 시스템이 **VMware**인지 탐지할 수도 있습니다.
- 다음과 같은 간단한 code를 사용하여 **프로세스가 debug되고 있는지** 확인할 수도 있습니다.
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- 또한 **`PT_DENY_ATTACH`** flag와 함께 **`ptrace`** system call을 호출할 수 있습니다. 이는 deb**u**gger가 attach하여 tracing하는 것을 **방지**합니다.
- **`sysctl`** 또는 **`ptrace`** function이 **import**되었는지 확인할 수 있습니다(단, malware가 이를 동적으로 import할 수도 있습니다).
- 이 writeup의 “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)”에 설명된 것처럼:\
“_Process # exited with **status = 45 (0x0000002d)** 메시지는 일반적으로 debug target이 **PT_DENY_ATTACH**를 사용하고 있다는 명확한 징후입니다._”

## Core Dumps

다음 조건에서는 core dumps가 생성됩니다.

- `kern.coredump` sysctl이 1로 설정된 경우(기본값)
- 프로세스가 suid/sgid가 아니거나 `kern.sugid_coredump`가 1인 경우(기본값은 0)
- `AS_CORE` limit이 작업을 허용하는 경우. `ulimit -c 0`을 호출하여 core dumps 생성을 비활성화하고, `ulimit -c unlimited`로 다시 활성화할 수 있습니다.

이러한 경우 core dumps는 `kern.corefile` sysctl 설정에 따라 생성되며, 일반적으로 `/cores/core/.%P`에 저장됩니다.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash는 **crashing process를 분석하고 crash report를 disk에 저장**합니다. crash report에는 **개발자가 crash의 원인을 진단하는 데 도움이 되는** 정보가 포함됩니다.\
**per-user launchd context에서 실행되는 application 및 기타 process**의 경우 ReportCrash는 LaunchAgent로 실행되며 crash report를 사용자의 `~/Library/Logs/DiagnosticReports/`에 저장합니다.\
daemon, **system launchd context에서 실행되는 기타 process** 및 기타 privileged process의 경우 ReportCrash는 LaunchDaemon으로 실행되며 crash report를 system의 `/Library/Logs/DiagnosticReports`에 저장합니다.

crash report가 **Apple로 전송되는 것**이 우려된다면 이를 비활성화할 수 있습니다. 그렇지 않다면 crash report는 **server가 crash한 원인을 파악하는 데** 유용할 수 있습니다.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### 절전

MacOS에서 fuzzing하는 동안 Mac이 절전 모드로 전환되지 않도록 하는 것이 중요합니다:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH 연결 끊김

SSH 연결을 통해 fuzzing하는 경우 세션이 끊기지 않도록 하는 것이 중요합니다. 따라서 다음과 같이 sshd_config 파일을 변경합니다:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Internal Handlers

**다음 페이지를 확인하여** 지정된 **scheme 또는 protocol을 처리하는** 앱을 찾는 방법을 알아보세요:


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### 네트워크 프로세스 열거

네트워크 데이터를 관리하는 프로세스를 찾는 데 유용합니다:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
또는 `netstat`이나 `lsof`를 사용합니다.

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI tools에서 작동합니다.

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

macOS GUI tools에서 "**그냥 작동합니다**". 일부 macOS 앱에는 고유한 파일 이름, 올바른 확장자, sandbox에서 파일을 읽어야 하는 등의 특정 요구 사항이 있다는 점에 유의하세요 (`~/Library/Containers/com.apple.Safari/Data`).

몇 가지 예시:
```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```
### MacOS Fuzzing 추가 정보

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## 참고 자료

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [The Art of Mac Malware, Volume I: Analysis](https://taomm.org/vol1/analysis.html)
- [4] [The Art of Mac Malware: The Guide to Analyzing Malicious Software](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
