# macOS 앱 - 검사, 디버깅 및 Fuzzing

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

### Disarm (old jtool2)

[**여기에서 disarm을 다운로드할 수 있습니다**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> **`disarm`**은 압축된 IM4P 파일(예: `kernelcache`)에서도 작동하며, 필요한 부분만 추출하거나 추출하지 않고 필요한 부분을 분석할 수도 있습니다.

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
> **`Codesign`**은 **macOS**에서, **`ldid`**는 **iOS**에서 찾을 수 있습니다.

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html)는 **.pkg** 파일(설치 프로그램)을 검사해 설치하기 전에 내부에 무엇이 있는지 확인할 때 유용한 도구입니다.\
이 설치 프로그램에는 `preinstall` 및 `postinstall` bash 스크립트가 포함되어 있으며, malware 작성자는 보통 이를 악용해 malware를 **persist**시킵니다.

### hdiutil

이 도구는 Apple 디스크 이미지(`.dmg`) 파일을 **mount**하여 실행 전에 검사할 수 있게 합니다:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

It will be mounted in `/Volumes`

### 패킹된 바이너리

- 엔트로피가 높은지 확인
- 문자열을 확인 (이해할 수 있는 문자열이 거의 없다면 패킹된 것)
- macOS용 UPX packer는 `__XHDR`라는 섹션을 생성합니다.

## 정적 Objective-C 분석

### 메타데이터

> [!CAUTION]
> Objective-C로 작성된 프로그램은 [Mach-O 바이너리](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)로 **컴파일된 후에도** 클래스 선언을 **유지**합니다. 이러한 클래스 선언에는 다음 항목의 이름과 타입이 **포함**됩니다.

- 정의된 인터페이스
- 인터페이스 메서드
- 인터페이스 인스턴스 변수
- 정의된 프로토콜

바이너리 리버싱을 어렵게 만들기 위해 이름을 난독화할 수도 있습니다.

### 함수 호출

Objective-C를 사용하는 바이너리에서 함수를 호출하면, 컴파일된 코드는 해당 함수를 직접 호출하는 대신 **`objc_msgSend`**를 호출합니다. 이 함수가 최종 함수를 호출합니다.

![메타데이터 - 함수 호출: Objective-C를 사용하는 바이너리에서 함수를 호출하면, 컴파일된 코드는 해당 함수를 직접 호출하는 대신 objc_msgSend를 호출합니다. 이 함수가 최종 함수를 호출합니다.](<../../../images/image (305).png>)

이 함수가 받는 매개변수는 다음과 같습니다.

- 첫 번째 매개변수(**self**)는 "메시지를 받을 클래스의 **인스턴스를 가리키는 포인터**"입니다. 간단히 말하면, 메서드가 호출되는 객체입니다. 메서드가 클래스 메서드라면 클래스 객체 전체의 인스턴스이며, 인스턴스 메서드라면 `self`는 인스턴스화된 클래스 객체를 가리킵니다.
- 두 번째 매개변수(**op**)는 "메시지를 처리하는 메서드의 셀렉터"입니다. 간단히 말하면, **메서드의 이름**입니다.
- 나머지 매개변수는 메서드(**op**)에 필요한 **값**입니다.

이 페이지에서 **ARM64의 `lldb`로 이 정보를 쉽게 얻는 방법**을 확인하세요.

{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **인수**          | **레지스터**                                                    | **objc_msgSend의 경우**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **첫 번째 인수**  | **rdi**                                                         | **self: 메서드가 호출되는 객체**                       |
| **두 번째 인수**  | **rsi**                                                         | **op: 메서드 이름**                                    |
| **세 번째 인수**  | **rdx**                                                         | **메서드의 첫 번째 인수**                              |
| **네 번째 인수**  | **rcx**                                                         | **메서드의 두 번째 인수**                              |
| **다섯 번째 인수** | **r8**                                                          | **메서드의 세 번째 인수**                              |
| **여섯 번째 인수** | **r9**                                                          | **메서드의 네 번째 인수**                              |
| **일곱 번째 이상 인수** | <p><strong>rsp+</strong><br><strong>(스택에)</strong></p> | **메서드의 다섯 번째 이상 인수**                       |

### ObjectiveC 메타데이터 덤프

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump)는 Objective-C 바이너리의 class-dump를 수행하는 도구입니다. GitHub 설명에는 dylibs가 언급되어 있지만 실행 파일에도 사용할 수 있습니다.

```bash
./dynadump dump /path/to/bin
```

작성 시점 기준으로 **현재 가장 잘 작동하는 방법입니다**.

#### 일반 도구

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/)는 Objective-C 형식 코드의 클래스, 카테고리 및 프로토콜에 대한 선언을 생성하는 원조 도구입니다.

오래되었고 유지 관리되지 않으므로 제대로 작동하지 않을 수 있습니다.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump)는 최신 크로스 플랫폼 Objective-C 클래스 덤프 도구입니다. 기존 도구와 비교해 iCDump는 Apple 생태계와 독립적으로 실행할 수 있으며 Python 바인딩을 제공합니다.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Static Swift 분석

Swift 바이너리는 Objective-C 호환성을 지원하므로, [class-dump](https://github.com/nygard/class-dump/)를 사용해 선언을 추출할 수 있는 경우도 있지만 항상 가능한 것은 아닙니다.

**`jtool -l`** 또는 **`otool -l`** 명령줄을 사용하면 **`__swift5`** 접두사로 시작하는 여러 섹션을 찾을 수 있습니다:

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

이 섹션에 저장된 [**정보에 대한 자세한 내용은 이 블로그 게시물**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)에서 확인할 수 있습니다.<sup>[[5]](#references)</sup>

또한 **Swift 바이너리에는 symbols가 있을 수 있습니다**(예를 들어, 라이브러리는 함수 호출에 필요한 symbols를 저장해야 합니다). **symbols에는 보통 함수 이름과 속성 정보가 난해한 형식으로 들어 있으므로** 매우 유용합니다. 원래 이름을 복원해 주는 "**demangler"**도 있습니다:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## 동적 분석

> [!WARNING]
> **기본 디버깅 단계로 SIP를 비활성화하지 마세요.** `com.apple.security.get-task-allow`가 설정된 개발 빌드는 SIP가 활성화된 상태에서도 디버깅할 수 있습니다. LLDB를 사용하기 전에 `codesign -d --entitlements :- /path/to/binary`로 대상을 확인하세요. 디버거 entitlement만으로는 SIP가 보호하는 대상에 접근할 수 없습니다.<sup>[[15]](#references)</sup>
>
> 배포된 앱은 hardened runtime을 사용하면서 보통 `get-task-allow`를 제외하므로 디버거 연결이 차단됩니다. 가능하다면 개발자가 제공한 디버그 빌드를 사용하세요. 임시 복사본에 다시 서명하면 테스트 대상의 동작이 바뀔 수 있습니다. 보호된 대상에 SIP 비활성화가 필요하다면, 의존하는 컴퓨터 대신 전용 테스트 컴퓨터나 VM을 사용하세요.<sup>[[16]](#references)</sup>

> [!WARNING]
> macOS에서 `cloudconfigurationd`와 같은 **시스템 바이너리를 계측하려면 SIP를 비활성화해야 합니다**(서명만 제거해서는 작동하지 않습니다).

### API

macOS는 프로세스 정보를 제공하는 몇 가지 유용한 API를 노출합니다.

- `proc_info`: 각 프로세스에 관한 많은 정보를 제공하는 주요 API입니다. 다른 프로세스의 정보를 얻으려면 root 권한이 필요하지만, 특별한 entitlement나 mach port는 필요하지 않습니다.
- `libsysmon.dylib`: XPC 함수를 통해 프로세스 정보를 노출하지만, 호출자에게는 `com.apple.sysmond.client` entitlement가 필요합니다.

### Stackshot 및 microstackshot

**Stackshotting**은 실행 중인 모든 스레드의 호출 스택을 포함해 프로세스 상태를 캡처하는 기법입니다. 특정 시점의 시스템 동작을 이해하고, 디버깅 및 성능 분석을 수행할 때 특히 유용합니다. iOS와 macOS에서는 **`sample`** 및 **`spindump`** 같은 도구와 여러 방법을 사용해 stackshotting을 수행할 수 있습니다.

### Sysdiagnose

이 도구(`/usr/bini/ysdiagnose`)는 `ps`, `zprint` 등 수십 가지 명령을 실행해 컴퓨터에서 많은 정보를 수집합니다.

이 도구는 **root**로 실행해야 하며, 데몬 `/usr/libexec/sysdiagnosed`에는 `com.apple.system-task-ports` 및 `get-task-allow`와 같은 매우 흥미로운 entitlement가 있습니다.

plist는 `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`에 있으며, 다음 3개의 MachService를 선언합니다.

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp의 오래된 아카이브를 삭제합니다
- `com.apple.sysdiagnose.kernel.ipc`: 특수 포트 23(kernel)
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C 클래스를 통한 사용자 모드 인터페이스입니다. dict에 세 개의 인수(`compress`, `display`, `run`)를 전달할 수 있습니다.

### 통합 로그

macOS는 애플리케이션 동작을 분석할 때 유용한 광범위한 로그를 생성합니다.

일부 로그 필드에는 사용자 또는 기기를 식별할 수 있는 정보를 숨기기 위해 `<private>` 태그가 포함됩니다. 이전 지침에서는 이러한 필드를 표시하기 위해 인증서를 설치하도록 설명하는 경우가 있습니다. 현재 디버깅 지침에서는 범위가 명시된 구성 프로파일의 `Enable-Private-Data` 또는 애플리케이션별 `OSLogPreferences`를 사용하며, 동작은 하위 시스템과 macOS 릴리스에 따라 달라질 수 있습니다. 이전의 인증서/프로파일 관련 설명은 참고 자료에 남아 있습니다. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### 왼쪽 패널

Hopper의 왼쪽 패널에서는 바이너리의 심볼(**Labels**), 프로시저와 함수 목록(**Proc**), 문자열(**Str**)을 볼 수 있습니다. 여기에 표시되는 문자열은 전체가 아니라 Mac-O 파일의 여러 영역(예: _cstring 또는 `objc_methname`)에 정의된 문자열입니다.

#### 가운데 패널

가운데 패널에서는 **디스어셈블된 코드**를 볼 수 있습니다. 해당 아이콘을 클릭하면 **raw** 디스어셈블, **그래프**, **디컴파일**, **바이너리** 보기로 확인할 수 있습니다.

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

코드 객체를 오른쪽 클릭하면 해당 객체를 **참조하는 위치와 해당 객체에서 참조하는 위치**를 확인하거나 이름을 바꿀 수 있습니다(디컴파일된 의사 코드에서는 작동하지 않습니다).

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

또한 **가운데 아래쪽에서 Python 명령을 작성할 수 있습니다**.

#### 오른쪽 패널

오른쪽 패널에서는 현재 상태에 도달한 경로를 확인할 수 있는 **탐색 기록**, 이 함수를 **호출하는 모든 함수**와 이 함수가 **호출하는 모든 함수**를 볼 수 있는 **호출 그래프**, 그리고 **지역 변수** 정보를 확인할 수 있습니다.

### dtrace

dtrace를 사용하면 애플리케이션에 **매우 낮은 수준**으로 접근할 수 있으며, **프로그램을 추적**하고 실행 흐름을 변경할 수도 있습니다. Dtrace는 **probe**를 사용합니다. probe는 **커널 곳곳에 배치**되며 시스템 호출의 시작과 끝 같은 위치에 있습니다.

DTrace는 **`dtrace_probe_create`** 함수를 사용해 각 시스템 호출에 probe를 생성합니다. 이 probe는 **각 시스템 호출의 진입점과 종료 지점에서** 실행될 수 있습니다. DTrace와의 상호작용은 root 사용자만 이용할 수 있는 /dev/dtrace를 통해 이루어집니다.<sup>[[1]](#references)</sup>

> [!TIP]
> SIP 보호 기능을 완전히 비활성화하지 않고 Dtrace를 활성화하려면 복구 모드에서 다음을 실행할 수 있습니다: `csrutil enable --without dtrace`
>
> 직접 **컴파일한** 바이너리에 **`dtrace`** 또는 **`dtruss`**를 사용할 수도 있습니다.

dtrace에서 사용 가능한 probe는 다음과 같이 확인할 수 있습니다:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

probe 이름은 네 부분, 즉 provider, module, function, name으로 구성됩니다(`fbt:mach_kernel:ptrace:entry`). 이름의 일부를 지정하지 않으면 Dtrace는 해당 부분을 와일드카드로 처리합니다.

DTrace가 probe를 활성화하고 probe가 실행될 때 수행할 동작을 지정하려면 D 언어를 사용해야 합니다.

자세한 설명과 예제는 [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)에서 확인할 수 있습니다.

#### 예제

`man -k dtrace`를 실행해 사용 가능한 **DTrace 스크립트**를 나열합니다. 예: `sudo dtruss -n binary`

- 인라인

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

커널 tracing 기능입니다. 문서화된 코드는 **`/usr/share/misc/trace.codes`**에서 확인할 수 있습니다.

`latency`, `sc_usage`, `fs_usage`, `trace`와 같은 도구는 내부적으로 이를 사용합니다.

`kdebug`와 연동하려면 `kern.kdebug` namespace의 `sysctl`을 사용합니다. 사용할 MIB는 `sys/sysctl.h`에서 확인할 수 있으며, 관련 함수는 `bsd/kern/kdebug.c`에 구현되어 있습니다.

custom client로 kdebug와 상호작용할 때는 일반적으로 다음 단계를 따릅니다.

- KERN_KDSETREMOVE로 기존 설정 제거
- KERN_KDSETBUF 및 KERN_KDSETUP으로 trace 설정
- KERN_KDGETBUF를 사용해 버퍼 항목 수 확인
- KERN_KDPINDEX로 trace에서 자체 client 가져오기
- KERN_KDENABLE로 tracing 활성화
- KERN_KDREADTR을 호출해 버퍼 읽기
- 각 thread를 프로세스와 연결하려면 KERN_KDTHRMAP 호출

이 정보를 얻으려면 Apple 도구인 **`trace`** 또는 custom 도구 [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**를 사용할 수 있습니다.

**Kdebug는 한 번에 사용자 한 명만 사용할 수 있습니다.** 따라서 k-debug 기반 도구는 한 번에 하나만 실행할 수 있습니다.

### ktrace

`ktrace_*` API는 `Kdebug` API를 래핑하는 `libktrace.dylib`에서 제공됩니다. 따라서 client는 `ktrace_session_create`와 `ktrace_events_[single/class]`를 호출해 특정 코드에 callback을 설정한 다음 `ktrace_start`로 시작하면 됩니다.

**SIP이 활성화된 상태에서도** 사용할 수 있습니다.

client로 `ktrace` 유틸리티를 사용할 수 있습니다:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

또는 `tailspin`.

### kperf

커널 수준 profiling에 사용되며 `Kdebug` callout을 사용해 빌드됩니다.

기본적으로 전역 변수 `kernel_debug_active`를 확인하고, 활성화되어 있으면 호출 중인 커널 프레임의 `Kdebug` 코드와 주소를 사용해 `kperf_kdebug_handler`를 호출합니다. `Kdebug` 코드가 선택된 코드와 일치하면 비트맵으로 구성된 "actions"가 적용됩니다(옵션은 `osfmk/kperf/action.h` 참조).

Kperf에는 sysctl MIB 테이블도 있습니다. (root 권한으로) `sysctl kperf`를 실행하면 됩니다. 관련 코드는 `osfmk/kperf/kperfbsd.c`에서 확인할 수 있습니다.

또한 Kperf 기능의 일부는 `kpc`에 있으며, 이 기능은 머신 성능 카운터 정보를 제공합니다.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor)는 프로세스가 수행하는 프로세스 관련 동작을 확인하는 데 유용한 도구입니다(예: 프로세스가 새로 생성하는 프로세스 모니터링).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/)는 프로세스 간 관계를 출력하는 도구입니다.\
**`sudo eslogger fork exec rename create > cap.json`** 같은 명령으로 Mac을 모니터링해야 합니다(이 명령을 실행하는 터미널에 FDA가 필요합니다). 그런 다음 이 도구에서 json 파일을 불러와 모든 관계를 확인할 수 있습니다.

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor)는 파일 생성, 수정, 삭제 등의 이벤트를 모니터링합니다.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo)는 Windows 사용자가 Microsoft Sysinternal의 _Procmon_에서 익숙하게 접할 수 있는 모양과 사용감을 갖춘 GUI 도구입니다. 이 도구를 사용하면 다양한 이벤트 유형의 기록을 시작하고 중지할 수 있고, 파일, 프로세스, 네트워크 등의 카테고리별로 이벤트를 필터링할 수 있으며, 기록한 이벤트를 json 형식으로 저장할 수 있습니다.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html)는 Xcode Developer tools의 일부로, 애플리케이션 성능 모니터링, 메모리 leak 식별, 파일시스템 활동 추적에 사용됩니다.

![Crescendo - Apple Instruments: Apple Instruments는 Xcode Developer tools의 일부로, 애플리케이션 성능 모니터링, 메모리 leak 식별, 파일시스템 활동 추적에 사용됩니다](<../../../images/image (1138).png>)

### fs_usage

프로세스가 수행하는 동작을 추적할 수 있습니다:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html)는 바이너리에서 사용하는 **라이브러리**, 사용 중인 **파일**, **네트워크** 연결을 확인하는 데 유용합니다.\
또한 바이너리 프로세스를 **virustotal**과 대조하고 바이너리 정보를 표시합니다.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**이 블로그 게시물**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)에서 SIP가 비활성화되어 있어도 디버깅을 막기 위해 **`PT_DENY_ATTACH`**를 사용한 **실행 중인 데몬을 디버깅하는** 예제를 확인할 수 있습니다.<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH`는 값이 **31**(`0x1f`)인 Darwin 전용 `ptrace(2)` 요청이며, 다른 인수는 무시됩니다. 프로세스는 fork하지 않고도 이를 직접 호출해 이후 부모 프로세스의 추적을 거부할 수 있습니다.<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### XNU 상태 및 호출 순서

결과는 어떤 `ptrace` 요청이 XNU에 먼저 도달하는지에 따라 달라집니다:<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB가 먼저 attach하는 경우:** `debugserver`는 `PT_ATTACHEXC`를 사용합니다. XNU는 이를 `PT_ATTACH`로 변환하고, `KAUTH_PROCESS_CANTRACE` 권한을 확인한 뒤 대상에 `P_LTRACED`를 설정합니다. 이후 `PT_DENY_ATTACH` 요청은 해당 플래그를 확인하고 `W_EXITCODE(ENOTSUP, 0)`으로 대상을 종료합니다. LLDB에는 보통 상태 **45**(`0x2d`)로 표시됩니다.
- **대상이 먼저 attach를 거부하는 경우:** XNU는 `P_LNOATTACH`를 설정합니다. 이후 attach는 process-tracing 권한 확인 단계에서 거부됩니다. attach 오류 처리 경로는 `P_LNOATTACH`를 확인하고 attach를 시도한 프로세스에 `SIGSEGV`를 전송합니다. 이로 인해 LLDB에서 `debugserver` 연결이 끊긴 것으로 표시될 수 있습니다.

이 경로를 구분하려면 실행 또는 attach 전에 `debugserver` 로깅을 활성화하고 해당 `ptrace` 요청을 확인하세요:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### ARM64 정적 식별 및 우회

난독화되지 않은 ARM64 Mach-O에서 가져온 `_ptrace` 스텁을 찾고 호출 지점을 확인합니다. 첫 번째 정수 인자는 `w0`으로 전달되므로, 이 명령어 시퀀스에서 anti-debug 요청을 직접 확인할 수 있습니다. 해당 import가 없다고 해서 결론을 내릴 수는 없습니다. 코드에서 `ptrace`를 동적으로 확인할 수도 있기 때문입니다. 가져온 `_sysctl`도 anti-debug 검사를 나타낼 수 있지만, 이 역시 동적으로 확인될 수 있습니다.<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

시연된 샘플에서 immediate 값을 `0x1f`에서 `0x0`으로 패치하면 요청이 `PT_TRACE_ME`로 바뀌고, 프로그램이 LLDB에서 계속 실행됩니다. 이는 **해당 샘플에만 적용되는 우회 방법**이지 일반적인 no-op이 아닙니다. 요청을 변경할지, 호출을 건너뛸지, 아니면 성공을 반환하도록 강제할지 결정하기 전에 호출자의 반환값 검사와 제어 흐름을 확인하세요.<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb**는 **macOS** 바이너리 **디버깅**을 위한 **사실상의 도구**입니다.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

LLDB를 사용할 때 홈 폴더에 다음 줄이 포함된 **`.lldbinit`** 파일을 만들어 Intel flavor를 설정할 수 있습니다:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> lldb 내부에서 `process save-core`로 프로세스를 덤프합니다.

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) 명령어</strong></td><td><strong>설명</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>실행을 시작합니다. breakpoint에 도달하거나 프로세스가 종료될 때까지 실행됩니다.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>실행을 시작하고 진입점에서 멈춥니다.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>디버깅 중인 프로세스의 실행을 계속합니다.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>다음 명령어를 실행합니다. 이 명령어는 함수 호출을 건너뜁니다.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>다음 명령어를 실행합니다. <code>nexti</code> 명령어와 달리 함수 호출 내부로 들어갑니다.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>현재 함수(frame)의 나머지 명령어를 실행한 뒤, 반환하고 멈춥니다.</td></tr>
<tr><td><strong>control + c</strong></td><td>실행을 일시 중지합니다. 프로세스가 실행(<code>r</code>)되었거나 계속 실행(<code>c</code>) 중이라면, 현재 실행 중인 위치에서 멈춥니다.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # main이라는 이름의 모든 함수</p>
<p><code>b &lt;binname&gt;`main</code> # 바이너리의 메인 함수</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # 지정한 바이너리의 메인 함수</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # 모든 NSFileManager 메서드</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # 해당 라이브러리의 모든 함수에서 멈춤</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # breakpoint 목록</p>
<p><code>br e/dis &lt;num&gt;</code> # breakpoint 활성화/비활성화</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # breakpoint 명령어 도움말 보기</p>
<p><code>help memory write</code> # 메모리 쓰기 도움말 보기</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>메모리를 null 종료 문자열로 표시합니다.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>메모리를 어셈블리 명령어로 표시합니다.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>메모리를 바이트로 표시합니다.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>매개변수가 참조하는 객체를 출력합니다.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>대부분의 Apple Objective-C API 또는 메서드는 객체를 반환하므로 “print object” (<code>po</code>) 명령어로 표시해야 합니다. <code>po</code>가 의미 있는 출력을 생성하지 않으면 <code>x/b</code>를 사용합니다.</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # 해당 주소에 AAAA 쓰기<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # 해당 주소에 AAAA 쓰기
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # 현재 함수 디스어셈블</p>
<p><code>dis -n &lt;funcname&gt;</code> # 함수 디스어셈블</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # 함수 디스어셈블<br>
<code>dis -c 6</code> # 6줄 디스어셈블<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # 한 주소에서 다른 주소까지 디스어셈블<br>
<code>dis -p -c 4</code> # 현재 주소부터 디스어셈블 시작</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # <code>x1</code> 레지스터에 있는 3개 요소 배열 검사</td></tr>
<tr><td><strong>image dump sections</strong></td><td>현재 프로세스 메모리 맵을 출력합니다.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # CoreNLP의 모든 심볼 주소 확인</td></tr>
</tbody>
</table>

> [!TIP]
> **`objc_sendMsg`** 함수를 호출할 때 **rsi** 레지스터에는 null 종료(“C”) 문자열로 된 **메서드 이름**이 들어 있습니다. lldb에서 이름을 출력하려면 다음을 실행합니다.
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### 동적 분석 방지

#### VM 탐지

- **`sysctl hw.model`** 명령어는 일반적으로 물리 하드웨어에서 Mac 모델 식별자를 반환하며, VM에서는 다른 값을 반환할 수 있습니다.<sup>[[3]](#references)</sup>
- 일부 malware는 **`hw.logicalcpu`** 및 **`hw.physicalcpu`** 값을 조작해 VM인지 탐지하려고 합니다.<sup>[[4]](#references)</sup>
- 일부 malware는 MAC 주소(00:50:56)를 바탕으로 시스템이 **VMware**인지도 **탐지**할 수 있습니다.
- 다음과 같은 간단한 코드로 **프로세스가 디버깅 중인지 탐지**할 수도 있습니다.
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- **`PT_DENY_ATTACH`** 플래그를 사용해 **`ptrace`** 시스템 호출을 실행할 수도 있습니다. 순서에 따라 달라지는 XNU 동작, `debugserver` 로깅 및 ARM64 패치 작업 과정은 [PT_DENY_ATTACH section](#page-title)을 확인하세요.<sup>[[7]](#references)[[12]](#references)</sup>

- **`PT_DENY_ATTACH`** 플래그를 사용해 **`ptrace`** 시스템 호출을 실행할 수도 있습니다. 이 플래그는 debugger가 연결해 추적하는 것을 **방지**합니다.
  - **`sysctl`** 또는 **`ptrace`** 함수가 **import**되는지 확인할 수 있습니다(단, malware가 동적으로 import할 수도 있습니다).
  - 이 writeup “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)”에서 설명하듯이:<sup>[[7]](#references)</sup>\
    “_Process # exited with **status = 45 (0x0000002d)**라는 메시지는 디버그 대상이 **PT_DENY_ATTACH**를 사용하고 있다는 명백한 신호인 경우가 많습니다._”
#### `fork()` 프로세스 전환

프로세스는 시작 직후 `fork()`를 호출하고 부모 프로세스를 종료한 뒤(`fork()`는 양수인 자식 PID를 반환), 자식 프로세스에서만 보호된 로직을 이어 실행함으로써 원래 PID에 계속 연결된 debugger를 회피할 수 있습니다(`fork()`는 `0`을 반환). `dlsym(RTLD_DEFAULT, "fork")`로 `fork`를 확인하면 직접적인 `_fork` 호출 지점도 사라지지만, 이는 분석을 어렵게 하는 방해 요소일 뿐입니다. 심볼 이름 문자열과 동적 해석의 데이터 흐름은 여전히 Mach-O 바이너리에서 확인할 수 있습니다.<sup>[[13]](#references)[[14]](#references)</sup>

arm64에서는 고정 주소가 아니라 데이터 흐름을 따라 이 패턴을 탐지합니다. `dlsym`의 처음 두 인수는 `x0`과 `x1`로 전달됩니다. `RTLD_DEFAULT`는 `-2`로 나타날 수 있으며(예: `movn x0, #1`), `"fork"` 문자열의 주소는 흔히 `adrp`/`add` 명령어 쌍으로 구성됩니다. `dlsym` stub으로 `bl`한 뒤 반환 포인터가 `x0`에서 null 검사와 저장을 거쳐 나중의 간접 `blr`까지 이어지는 흐름을 추적합니다. 이어서 `w0`의 `fork()` 결과를 따라가면 `0`은 자식 프로세스의 실행 경로를 선택하고, 양수 및 `-1` 값은 부모/오류 경로를 선택합니다.<sup>[[13]](#references)[[14]](#references)</sup>

정적 우회 방법은 간접 호출을 억제하고 기존 결과 검사가 자식 프로세스 경로를 선택하도록 하는 것입니다. 예를 들어 컴파일러가 아래와 같은 시퀀스를 생성했다면, `blr`과 결과 저장 명령어를 `nop`으로 패치하고 가상의 `0` 결과를 제공한 뒤 비교/분기 로직은 그대로 유지할 수 있습니다. 그러면 자식 프로세스를 만들지 않고 원래 PID에서 애플리케이션이 계속 실행됩니다. 명령어 레지스터와 분기 대상은 분석 중인 빌드에 맞게 조정해야 합니다.<sup>[[13]](#references)[[14]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## 코어 덤프

코어 덤프는 다음과 같은 경우 생성됩니다.

- `kern.coredump` sysctl이 1로 설정된 경우(기본값)
- 프로세스가 suid/sgid가 아니거나 `kern.sugid_coredump`가 1인 경우(기본값은 0)
- `AS_CORE` 제한이 작업을 허용하는 경우. `ulimit -c 0`을 호출해 코어 덤프 생성을 비활성화하고 `ulimit -c unlimited`로 다시 활성화할 수 있습니다.

이 경우 코어 덤프는 `kern.corefile` sysctl 설정에 따라 생성되며, 보통 `/cores/core/.%P`에 저장됩니다.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash는 **충돌한 프로세스를 분석하고 충돌 보고서를 디스크에 저장합니다**. 충돌 보고서에는 개발자가 충돌 원인을 진단하는 데 **도움이 되는** 정보가 포함됩니다.\
**사용자별 launchd 컨텍스트에서 실행되는** 애플리케이션 및 기타 프로세스의 경우, ReportCrash는 LaunchAgent로 실행되며 충돌 보고서를 사용자의 `~/Library/Logs/DiagnosticReports/`에 저장합니다.\
데몬, **시스템 launchd 컨텍스트에서 실행되는** 기타 프로세스 및 기타 권한이 있는 프로세스의 경우, ReportCrash는 LaunchDaemon으로 실행되며 충돌 보고서를 시스템의 `/Library/Logs/DiagnosticReports`에 저장합니다.

충돌 보고서가 **Apple로 전송되는 것**이 걱정된다면 비활성화할 수 있습니다. 그렇지 않다면 충돌 보고서를 통해 **서버가 충돌한 원인을 파악**할 수 있습니다.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### 절전

macOS에서 fuzzing을 수행하는 동안 Mac이 절전 모드에 들어가지 않도록 합니다.

- systemsetup -setsleep Never
- pmset, 시스템 환경설정
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH 연결 끊김

SSH 연결을 통해 fuzzing을 수행하는 경우 세션이 끊기지 않도록 해야 합니다. 따라서 다음과 같이 sshd_config 파일을 변경합니다.

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### 내부 핸들러

**다음 페이지를 확인하여** 지정된 scheme 또는 protocol을 **처리하는 앱을 찾는 방법을 알아보세요:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### 네트워크 프로세스 열거

네트워크 데이터를 관리하는 프로세스를 찾을 때 유용합니다:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

또는 `netstat`이나 `lsof`를 사용하세요.

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Stateful Mach IPC fuzzing

권한이 높은 daemon이 노출하는 Mach 서비스는 권한이 없거나 sandbox에 격리된 클라이언트가 send right를 얻을 수 있는 경우 유용한 fuzzing 대상입니다. daemon의 `MachServices` launchd 항목에서 시작해 [MIG 분석 워크플로](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)를 사용하여 메시지 ID와 핸들러를 매핑합니다. 바이트를 변형하기 전에 정상 클라이언트가 서비스를 사용하는 동안 MIG 서버 루틴에 중단점을 설정하고, 유효한 요청 메시지를 seed input으로 저장합니다. 변형된 메시지가 dispatch 단계에서 즉시 실패하지 않고 핸들러에 도달하도록 필수 헤더 필드, 메시지 크기, descriptor 레이아웃을 유지합니다.<sup>[[17]](#references)</sup>

많은 핸들러는 이전 호출에 의존합니다. harness에서 서비스 상태를 초기화한 다음, 각 fuzz input을 **연산과 인수**의 시퀀스로 처리합니다. 설정 요청(예: open 또는 create)을 보내고 반환된 식별자를 보관한 뒤, 후속 요청에서 사용합니다. 이렇게 하면 coverage feedback으로 초기화되지 않은 객체 검사에 계속 걸리는 대신 상태 전이를 탐색할 수 있습니다.<sup>[[17]](#references)</sup>

소스가 공개되지 않은 대상의 경우, MIG dispatch 루틴을 호출하는 in-process harness에 Jackalope/TinyInst를 사용해 계측할 수 있습니다. [CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)는 구체적인 구현이며, 다른 서비스에 그대로 사용할 수 있는 harness는 아닙니다.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**모든 crash를 실제 IPC 경로를 통해 검증하세요.** 직접 dispatch하는 harness는 Mach 메시지에 대한 커널 검증을 건너뛰므로, 특히 유효하지 않은 out-of-line (OOL) 메모리나 port descriptor를 제공할 경우 false positive가 발생할 수 있습니다. harness에서 유효한 OOL backing memory를 할당한 다음, 원래 서비스 접근 권한을 가진 클라이언트에서 `mach_msg`를 통해 축소된 testcase를 재현하고 daemon이 여전히 crash하는지 확인합니다.<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI 도구에서 작동합니다.

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

많은 macOS GUI 도구에서 "**그냥 작동합니다**". 일부 애플리케이션에는 고유한 파일 이름, 특정 확장자, 또는 sandbox 컨테이너(`~/Library/Containers/com.apple.Safari/Data`)에서 파일을 읽는 것과 같은 추가 요구 사항이 있습니다.

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

### macOS Fuzzing 추가 정보

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)



## References

- [1] [OS X 인시던트 대응: 스크립팅 및 분석](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Fuzz의 여름: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Mac 악성코드 분석의 기술, 제1권: 분석](https://taomm.org/)
- [4] [No Starch Press - Mac 악성코드 분석의 기술: 악성 소프트웨어 분석 가이드](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - 이 블로그 게시물의 해당 섹션에 저장된 정보](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - `Pt Deny Attach`를 사용하는 Apple 바이너리 디버깅](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Anti-Debug 기법 무력화: macOS ptrace 변형](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Xcode 구조화 로그 및 `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - macOS 통합 로그에서 비공개 데이터 표시하기](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Apple XNU `ptrace.h` 요청 정의](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Apple XNU `mach_process.c`의 `ptrace` 구현](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - ptrace 내부 동작: 디버거 연결을 방지하는 방법](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - fork 예제](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - dlsym과 fork를 사용하는 Anti-Debug 기법](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - 디버깅 도구 entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - 강화된 서드파티 앱 디버깅](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - 음속 장벽 돌파 1부: Mach 메시지로 CoreAudio Fuzzing하기](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - CoreAudioFuzz 하네스](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Jackalope fuzzer](https://github.com/googleprojectzero/Jackalope)
{{#include ../../../banners/hacktricks-training.md}}
