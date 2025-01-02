# macOS 앱 - 검사, 디버깅 및 퍼징

{{#include ../../../banners/hacktricks-training.md}}

## 정적 분석

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
### jtool2 & Disarm

여기에서 [**disarm을 다운로드할 수 있습니다**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
여기에서 [**jtool2를 다운로드할 수 있습니다**](http://www.newosxbook.com/tools/jtool.html) 또는 `brew`로 설치할 수 있습니다.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
> [!CAUTION] > **jtool은 disarm으로 대체되었습니다**

### Codesign / ldid

> [!TIP] > **`Codesign`**은 **macOS**에서 찾을 수 있으며 **`ldid`**는 **iOS**에서 찾을 수 있습니다
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html)는 **.pkg** 파일(설치 프로그램)을 검사하고 설치하기 전에 내부 내용을 확인하는 데 유용한 도구입니다.\
이 설치 프로그램에는 악성 코드 작성자가 일반적으로 **악성 코드**를 **지속**시키기 위해 악용하는 `preinstall` 및 `postinstall` bash 스크립트가 포함되어 있습니다.

### hdiutil

이 도구는 Apple 디스크 이미지(**.dmg**) 파일을 **마운트**하여 실행하기 전에 검사할 수 있도록 합니다:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
It will be mounted in `/Volumes`

### Packed binaries

- 높은 엔트로피 확인
- 문자열 확인 (이해할 수 있는 문자열이 거의 없으면, 패킹됨)
- MacOS용 UPX 패커는 "\_\_XHDR"라는 섹션을 생성합니다.

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> Objective-C로 작성된 프로그램은 [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)로 컴파일될 때 **클래스 선언을 유지**합니다. 이러한 클래스 선언에는 다음이 포함됩니다:

- 정의된 인터페이스
- 인터페이스 메서드
- 인터페이스 인스턴스 변수
- 정의된 프로토콜

이 이름들은 이진 파일의 리버싱을 더 어렵게 만들기 위해 난독화될 수 있습니다.

### Function calling

Objective-C를 사용하는 이진 파일에서 함수가 호출될 때, 컴파일된 코드는 해당 함수를 호출하는 대신 **`objc_msgSend`**를 호출합니다. 이는 최종 함수를 호출하게 됩니다:

![](<../../../images/image (305).png>)

이 함수가 기대하는 매개변수는 다음과 같습니다:

- 첫 번째 매개변수 (**self**)는 "메시지를 받을 **클래스의 인스턴스를 가리키는 포인터**"입니다. 더 간단히 말하면, 이는 메서드가 호출되는 객체입니다. 메서드가 클래스 메서드인 경우, 이는 클래스 객체의 인스턴스(전체)이며, 인스턴스 메서드의 경우, self는 클래스의 인스턴스화된 인스턴스를 객체로 가리킵니다.
- 두 번째 매개변수 (**op**)는 "메시지를 처리하는 메서드의 선택자"입니다. 다시 말해, 이는 단순히 **메서드의 이름**입니다.
- 나머지 매개변수는 메서드(op)에 의해 필요한 **값들**입니다.

이 정보를 **ARM64에서 `lldb`로 쉽게 얻는 방법**은 이 페이지를 참조하세요:

{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self: 메서드가 호출되는 객체**                     |
| **2nd argument**  | **rsi**                                                         | **op: 메서드의 이름**                                 |
| **3rd argument**  | **rdx**                                                         | **메서드에 대한 1번째 인자**                          |
| **4th argument**  | **rcx**                                                         | **메서드에 대한 2번째 인자**                          |
| **5th argument**  | **r8**                                                          | **메서드에 대한 3번째 인자**                          |
| **6th argument**  | **r9**                                                          | **메서드에 대한 4번째 인자**                          |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(스택에서)</strong></p> | **메서드에 대한 5번째+ 인자**                         |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump)는 Objective-C 이진 파일을 클래스 덤프하는 도구입니다. GitHub에서는 dylibs를 명시하지만, 실행 파일에도 작동합니다.
```bash
./dynadump dump /path/to/bin
```
작성 당시, 이것이 **현재 가장 잘 작동하는 것**입니다.

#### 일반 도구
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/)는 Objective-C 형식의 코드에서 클래스, 카테고리 및 프로토콜에 대한 선언을 생성하는 원래 도구입니다.

오래되었고 유지 관리되지 않아서 제대로 작동하지 않을 수 있습니다.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump)는 현대적이고 크로스 플랫폼 Objective-C 클래스 덤프입니다. 기존 도구와 비교할 때, iCDump는 Apple 생태계와 독립적으로 실행될 수 있으며 Python 바인딩을 노출합니다.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Static Swift 분석

Swift 바이너리의 경우, Objective-C 호환성 덕분에 때때로 [class-dump](https://github.com/nygard/class-dump/)를 사용하여 선언을 추출할 수 있지만 항상 가능한 것은 아닙니다.

**`jtool -l`** 또는 **`otool -l`** 명령어를 사용하면 **`__swift5`** 접두사로 시작하는 여러 섹션을 찾을 수 있습니다:
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
이 섹션에 저장된 [**정보에 대한 추가 정보는 이 블로그 게시물에서 확인할 수 있습니다**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

게다가, **Swift 바이너리는 기호를 가질 수 있습니다** (예: 라이브러리는 함수가 호출될 수 있도록 기호를 저장해야 합니다). **기호는 일반적으로 함수 이름과 속성에 대한 정보를 보기 좋지 않게 가지고 있으므로 매우 유용하며, 원래 이름을 얻을 수 있는 "**demanglers"**가 있습니다:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## 동적 분석

> [!WARNING]
> 이진 파일을 디버깅하려면 **SIP를 비활성화해야 합니다** (`csrutil disable` 또는 `csrutil enable --without debug`) 또는 이진 파일을 임시 폴더로 복사하고 `codesign --remove-signature <binary-path>`로 **서명을 제거해야 하며**, 이진 파일의 디버깅을 허용해야 합니다 (이 [스크립트](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)를 사용할 수 있습니다).

> [!WARNING]
> macOS에서 **시스템 이진 파일**(예: `cloudconfigurationd`)을 **계측**하려면 **SIP를 비활성화해야 합니다** (서명만 제거하는 것으로는 작동하지 않습니다).

### API

macOS는 프로세스에 대한 정보를 제공하는 몇 가지 흥미로운 API를 노출합니다:

- `proc_info`: 각 프로세스에 대한 많은 정보를 제공하는 주요 API입니다. 다른 프로세스 정보를 얻으려면 루트 권한이 필요하지만, 특별한 권한이나 mach 포트는 필요하지 않습니다.
- `libsysmon.dylib`: XPC로 노출된 함수를 통해 프로세스에 대한 정보를 얻을 수 있게 해주지만, `com.apple.sysmond.client` 권한이 필요합니다.

### 스택샷 및 마이크로스택샷

**스택샷팅**은 프로세스의 상태를 캡처하는 기술로, 모든 실행 중인 스레드의 호출 스택을 포함합니다. 이는 디버깅, 성능 분석 및 특정 시점에서 시스템의 동작을 이해하는 데 특히 유용합니다. iOS 및 macOS에서는 **`sample`** 및 **`spindump`**와 같은 여러 도구와 방법을 사용하여 스택샷팅을 수행할 수 있습니다.

### Sysdiagnose

이 도구(`/usr/bini/ysdiagnose`)는 기본적으로 `ps`, `zprint`와 같은 수십 가지 명령을 실행하여 컴퓨터에서 많은 정보를 수집합니다...

루트 권한으로 실행해야 하며, 데몬 `/usr/libexec/sysdiagnosed`는 `com.apple.system-task-ports` 및 `get-task-allow`와 같은 매우 흥미로운 권한을 가지고 있습니다.

그의 plist는 `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`에 위치하며, 3개의 MachServices를 선언합니다:

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp의 오래된 아카이브를 삭제합니다.
- `com.apple.sysdiagnose.kernel.ipc`: 특별 포트 23 (커널)
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C 클래스를 통한 사용자 모드 인터페이스. 사전 정의된 세 가지 인자를 딕셔너리로 전달할 수 있습니다 (`compress`, `display`, `run`)

### 통합 로그

MacOS는 애플리케이션을 실행할 때 **무엇을 하고 있는지** 이해하는 데 매우 유용할 수 있는 많은 로그를 생성합니다.

게다가, `<private>` 태그가 포함된 로그가 있어 **사용자** 또는 **컴퓨터** **식별 가능한** 정보를 **숨깁니다**. 그러나 이 정보를 **공개하기 위해 인증서를 설치할 수 있습니다**. [**여기**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)의 설명을 따르세요.

### Hopper

#### 왼쪽 패널

Hopper의 왼쪽 패널에서는 이진 파일의 기호(**Labels**), 절차 및 함수 목록(**Proc**), 문자열(**Str**)을 볼 수 있습니다. 이들은 모든 문자열이 아니라 Mac-O 파일의 여러 부분에 정의된 문자열입니다 (예: _cstring 또는_ `objc_methname`).

#### 중간 패널

중간 패널에서는 **디스어셈블된 코드**를 볼 수 있습니다. 원시 디스어셈블, 그래프, 디컴파일된 코드 및 이진 코드로 각각의 아이콘을 클릭하여 볼 수 있습니다:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

코드 객체를 오른쪽 클릭하면 **해당 객체에 대한 참조**를 보거나 이름을 변경할 수 있습니다 (이것은 디컴파일된 의사 코드에서는 작동하지 않습니다):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

또한, **중간 하단에서 파이썬 명령을 작성할 수 있습니다**.

#### 오른쪽 패널

오른쪽 패널에서는 **탐색 기록**(현재 상황에 도달한 방법을 알 수 있음), **호출 그래프**(이 함수를 호출하는 모든 **함수**와 이 함수가 호출하는 모든 **함수**를 볼 수 있음), 및 **로컬 변수** 정보를 포함한 흥미로운 정보를 볼 수 있습니다.

### dtrace

사용자가 애플리케이션에 매우 **저수준**으로 접근할 수 있게 해주며, 프로그램을 **추적**하고 실행 흐름을 변경할 수 있는 방법을 제공합니다. Dtrace는 **프로브**를 사용하며, 이는 **커널 전역에 배치**되어 있으며 시스템 호출의 시작과 끝과 같은 위치에 있습니다.

DTrace는 각 시스템 호출에 대한 프로브를 생성하기 위해 **`dtrace_probe_create`** 함수를 사용합니다. 이러한 프로브는 각 시스템 호출의 **진입 및 종료 지점**에서 발사될 수 있습니다. DTrace와의 상호작용은 /dev/dtrace를 통해 이루어지며, 이는 루트 사용자만 사용할 수 있습니다.

> [!TIP]
> SIP 보호를 완전히 비활성화하지 않고 Dtrace를 활성화하려면 복구 모드에서 다음을 실행할 수 있습니다: `csrutil enable --without dtrace`
>
> 또한 **`dtrace`** 또는 **`dtruss`** 이진 파일을 **컴파일하여 사용할 수 있습니다**.

dtrace의 사용 가능한 프로브는 다음과 같이 얻을 수 있습니다:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
프로브 이름은 네 부분으로 구성됩니다: 제공자, 모듈, 함수 및 이름 (`fbt:mach_kernel:ptrace:entry`). 이름의 일부를 지정하지 않으면, Dtrace는 해당 부분을 와일드카드로 적용합니다.

DTrace를 구성하여 프로브를 활성화하고 프로브가 작동할 때 수행할 작업을 지정하려면 D 언어를 사용해야 합니다.

자세한 설명과 더 많은 예제는 [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)에서 확인할 수 있습니다.

#### 예제

`man -k dtrace`를 실행하여 **사용 가능한 DTrace 스크립트**를 나열합니다. 예: `sudo dtruss -n binary`
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
- 스크립트
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

커널 추적 기능입니다. 문서화된 코드는 **`/usr/share/misc/trace.codes`**에서 찾을 수 있습니다.

`latency`, `sc_usage`, `fs_usage` 및 `trace`와 같은 도구는 내부적으로 이를 사용합니다.

`kdebug`와 인터페이스하기 위해 `sysctl`은 `kern.kdebug` 네임스페이스를 통해 사용되며, 사용할 MIB는 `bsd/kern/kdebug.c`에 구현된 함수가 있는 `sys/sysctl.h`에서 찾을 수 있습니다.

커스텀 클라이언트로 kdebug와 상호작용하기 위한 일반적인 단계는 다음과 같습니다:

- KERN_KDSETREMOVE로 기존 설정 제거
- KERN_KDSETBUF 및 KERN_KDSETUP으로 추적 설정
- KERN_KDGETBUF로 버퍼 항목 수 가져오기
- KERN_KDPINDEX로 추적에서 자신의 클라이언트 가져오기
- KERN_KDENABLE로 추적 활성화
- KERN_KDREADTR 호출로 버퍼 읽기
- 각 스레드를 해당 프로세스와 일치시키기 위해 KERN_KDTHRMAP 호출.

이 정보를 얻기 위해 Apple 도구 **`trace`** 또는 커스텀 도구 [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**를 사용할 수 있습니다.**

**Kdebug는 한 번에 1명의 고객에게만 제공된다는 점에 유의하십시오.** 따라서 동시에 실행할 수 있는 k-debug 기반 도구는 하나뿐입니다.

### ktrace

`ktrace_*` API는 `libktrace.dylib`에서 제공되며, 이는 `Kdebug`의 래퍼입니다. 그런 다음 클라이언트는 `ktrace_session_create` 및 `ktrace_events_[single/class]`를 호출하여 특정 코드에 대한 콜백을 설정하고 `ktrace_start`로 시작할 수 있습니다.

**SIP가 활성화된 상태에서도 이 도구를 사용할 수 있습니다.**

클라이언트로는 유틸리티 `ktrace`를 사용할 수 있습니다:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
또는 `tailspin`.

### kperf

이것은 커널 수준 프로파일링을 수행하는 데 사용되며 `Kdebug` 호출을 사용하여 구축되었습니다.

기본적으로, 전역 변수 `kernel_debug_active`가 확인되고 설정되면 `Kdebug` 코드와 호출하는 커널 프레임의 주소로 `kperf_kdebug_handler`를 호출합니다. `Kdebug` 코드가 선택된 것과 일치하면 비트맵으로 구성된 "작업"을 가져옵니다(옵션은 `osfmk/kperf/action.h`를 확인하십시오).

Kperf에는 sysctl MIB 테이블도 있습니다: (루트로) `sysctl kperf`. 이 코드는 `osfmk/kperf/kperfbsd.c`에서 찾을 수 있습니다.

게다가, Kperf의 기능의 하위 집합은 `kpc`에 존재하며, 이는 머신 성능 카운터에 대한 정보를 제공합니다.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor)는 프로세스가 수행하는 프로세스 관련 작업을 확인하는 데 매우 유용한 도구입니다(예: 프로세스가 생성하는 새로운 프로세스를 모니터링).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/)는 프로세스 간의 관계를 인쇄하는 도구입니다.\
**`sudo eslogger fork exec rename create > cap.json`**와 같은 명령으로 Mac을 모니터링해야 합니다(이를 실행하는 터미널은 FDA가 필요합니다). 그런 다음 이 도구에서 json을 로드하여 모든 관계를 볼 수 있습니다:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor)는 파일 이벤트(생성, 수정 및 삭제와 같은)를 모니터링하여 이러한 이벤트에 대한 자세한 정보를 제공합니다.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo)는 Windows 사용자가 Microsoft Sysinternal의 _Procmon_에서 알 수 있는 모양과 느낌을 가진 GUI 도구입니다. 이 도구는 다양한 이벤트 유형의 기록을 시작하고 중지할 수 있으며, 파일, 프로세스, 네트워크 등과 같은 카테고리별로 이러한 이벤트를 필터링할 수 있는 기능을 제공하고, 기록된 이벤트를 json 형식으로 저장할 수 있는 기능을 제공합니다.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html)는 Xcode의 개발자 도구의 일부로, 애플리케이션 성능 모니터링, 메모리 누수 식별 및 파일 시스템 활동 추적에 사용됩니다.

![](<../../../images/image (1138).png>)

### fs_usage

프로세스가 수행하는 작업을 추적할 수 있습니다:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html)는 이진 파일에서 사용되는 **라이브러리**, 사용 중인 **파일** 및 **네트워크** 연결을 확인하는 데 유용합니다.\
또한 이진 프로세스를 **virustotal**과 대조하여 이진 파일에 대한 정보를 보여줍니다.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**이 블로그 게시물**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)에서는 **`PT_DENY_ATTACH`**를 사용하여 디버깅을 방지하는 **실행 중인 데몬**을 **디버깅하는** 방법에 대한 예제를 찾을 수 있습니다. 

### lldb

**lldb**는 **macOS** 이진 **디버깅**을 위한 사실상의 도구입니다.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
홈 폴더에 **`.lldbinit`**라는 파일을 생성하고 다음 줄을 추가하여 intel flavour를 설정할 수 있습니다:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> lldb 내에서 `process save-core`로 프로세스를 덤프합니다.

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) 명령어</strong></td><td><strong>설명</strong></td></tr><tr><td><strong>run (r)</strong></td><td>실행을 시작하며, 중단점이 hit되거나 프로세스가 종료될 때까지 계속됩니다.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>진입점에서 중단하며 실행을 시작합니다.</td></tr><tr><td><strong>continue (c)</strong></td><td>디버그된 프로세스의 실행을 계속합니다.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>다음 명령어를 실행합니다. 이 명령어는 함수 호출을 건너뜁니다.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>다음 명령어를 실행합니다. nexti 명령어와 달리, 이 명령어는 함수 호출로 들어갑니다.</td></tr><tr><td><strong>finish (f)</strong></td><td>현재 함수(“프레임”)의 나머지 명령어를 실행하고 반환 후 중단합니다.</td></tr><tr><td><strong>control + c</strong></td><td>실행을 일시 중지합니다. 프로세스가 run (r) 또는 continue (c)로 실행된 경우, 현재 실행 중인 위치에서 프로세스가 중단됩니다.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> # main이라고 호출된 모든 함수</p><p><code>b &#x3C;binname>`main</code> # bin의 main 함수</p><p><code>b set -n main --shlib &#x3C;lib_name></code> # 지정된 bin의 main 함수</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # 모든 NSFileManager 메서드</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # 해당 라이브러리의 모든 함수에서 중단</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> # 중단점 목록</p><p><code>br e/dis &#x3C;num></code> # 중단점 활성화/비활성화</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint # 중단점 명령어 도움말</p><p>help memory write # 메모리에 쓰기 위한 도움말</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>메모리를 null로 종료된 문자열로 표시합니다.</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>메모리를 어셈블리 명령어로 표시합니다.</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>메모리를 바이트로 표시합니다.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>이 명령어는 매개변수로 참조된 객체를 출력합니다.</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Apple의 대부분의 Objective-C API 또는 메서드는 객체를 반환하므로, “print object” (po) 명령어를 통해 표시해야 합니다. po가 의미 있는 출력을 생성하지 않으면 <code>x/b</code>를 사용하세요.</p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 # 해당 주소에 AAAA 쓰기<br>memory write -f s $rip+0x11f+7 "AAAA" # 해당 주소에 AAAA 쓰기</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis # 현재 함수의 디스어셈블리</p><p>dis -n &#x3C;funcname> # 함수의 디스어셈블리</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> # 함수의 디스어셈블리<br>dis -c 6 # 6줄 디스어셈블리<br>dis -c 0x100003764 -e 0x100003768 # 한 주소에서 다른 주소까지<br>dis -p -c 4 # 현재 주소에서 디스어셈블리 시작</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # x1 레지스터의 3개 구성 요소 배열 확인</td></tr><tr><td><strong>image dump sections</strong></td><td>현재 프로세스 메모리의 맵을 출력합니다.</td></tr><tr><td><strong>image dump symtab &#x3C;library></strong></td><td><code>image dump symtab CoreNLP</code> # CoreNLP의 모든 기호 주소 가져오기</td></tr></tbody></table>

> [!NOTE]
> **`objc_sendMsg`** 함수를 호출할 때, **rsi** 레지스터는 null로 종료된 (“C”) 문자열로서 **메서드의 이름**을 보유합니다. lldb를 통해 이름을 출력하려면 다음을 수행합니다:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### 안티 다이내믹 분석

#### VM 탐지

- **`sysctl hw.model`** 명령어는 **호스트가 MacOS**일 때 "Mac"을 반환하지만, VM일 경우 다른 값을 반환합니다.
- **`hw.logicalcpu`** 및 **`hw.physicalcpu`**의 값을 조작하여 일부 악성코드는 VM인지 감지하려고 합니다.
- 일부 악성코드는 MAC 주소(00:50:56)를 기반으로 **VMware**인지도 **탐지**할 수 있습니다.
- 간단한 코드로 **프로세스가 디버그되고 있는지** 확인할 수 있습니다:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //디버그 중인 프로세스 }`
- **`ptrace`** 시스템 호출을 **`PT_DENY_ATTACH`** 플래그와 함께 호출할 수도 있습니다. 이는 디버거가 연결하고 추적하는 것을 **방지**합니다.
- **`sysctl`** 또는 **`ptrace`** 함수가 **가져와지는지** 확인할 수 있습니다 (하지만 악성코드는 동적으로 가져올 수 있습니다).
- 이 글에서 언급된 바와 같이, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Process # exited with **status = 45 (0x0000002d)** 메시지는 디버그 대상이 **PT_DENY_ATTACH**를 사용하고 있다는 신호입니다._”

## 코어 덤프

코어 덤프는 다음과 같은 경우에 생성됩니다:

- `kern.coredump` sysctl이 1로 설정되어 있을 때 (기본값)
- 프로세스가 suid/sgid가 아니거나 `kern.sugid_coredump`가 1일 때 (기본값은 0)
- `AS_CORE` 제한이 작업을 허용할 때. `ulimit -c 0`을 호출하여 코드 덤프 생성을 억제할 수 있으며, `ulimit -c unlimited`로 다시 활성화할 수 있습니다.

이 경우 코어 덤프는 `kern.corefile` sysctl에 따라 생성되며, 일반적으로 `/cores/core/.%P`에 저장됩니다.

## 퍼징

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash는 **충돌하는 프로세스를 분석하고 충돌 보고서를 디스크에 저장합니다**. 충돌 보고서에는 **개발자가 충돌 원인을 진단하는 데 도움이 되는 정보**가 포함되어 있습니다.\
사용자별 launchd 컨텍스트에서 **실행되는 애플리케이션 및 기타 프로세스**에 대해 ReportCrash는 LaunchAgent로 실행되며, 사용자의 `~/Library/Logs/DiagnosticReports/`에 충돌 보고서를 저장합니다.\
데몬, 시스템 launchd 컨텍스트에서 **실행되는 기타 프로세스** 및 기타 권한 있는 프로세스에 대해 ReportCrash는 LaunchDaemon으로 실행되며, 시스템의 `/Library/Logs/DiagnosticReports`에 충돌 보고서를 저장합니다.

충돌 보고서가 **Apple로 전송되는 것에 대해 걱정된다면** 이를 비활성화할 수 있습니다. 그렇지 않으면, 충돌 보고서는 **서버가 어떻게 충돌했는지 알아내는 데 유용할 수 있습니다**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### 수면

MacOS에서 퍼징할 때 Mac이 잠들지 않도록 하는 것이 중요합니다:

- systemsetup -setsleep Never
- pmset, 시스템 환경설정
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH 연결 끊김

SSH 연결을 통해 퍼징하는 경우 세션이 종료되지 않도록 하는 것이 중요합니다. 따라서 sshd_config 파일을 다음과 같이 변경하십시오:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Internal Handlers

**다음 페이지를 확인하세요** 어떤 앱이 **지정된 스킴 또는 프로토콜을 처리하는지 찾는 방법을 알아보세요:**

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerating Network Processes

네트워크 데이터를 관리하는 프로세스를 찾는 것은 흥미롭습니다:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
`netstat` 또는 `lsof`를 사용하세요.

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI 도구에 적합합니다.

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

macOS GUI 도구와 "**그냥 작동"**합니다. 일부 macOS 앱은 고유한 파일 이름, 올바른 확장자와 같은 특정 요구 사항이 있으며, 샌드박스에서 파일을 읽어야 합니다 (`~/Library/Containers/com.apple.Safari/Data`)...

몇 가지 예:
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
### 더 많은 Fuzzing MacOS 정보

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## 참고문헌

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
