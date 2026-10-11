# KernelFlirt를 사용한 Windows 커널 디버깅

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt는 통제된 reverse-engineering 실습 환경을 위한 Windows x64 debugger입니다. 호스트 측 WPF UI 또는 `KfConsole.exe`가 테스트 서명된 Windows VM의 `KfRelay.exe`에 명령을 보냅니다. relay는 명령을 `KernelFlirt.sys`용 `DeviceIoControl` 요청으로 변환하며, 이 드라이버는 메모리, 레지스터, breakpoint, 실행 제어 및 커널 모듈 작업을 제공합니다. 또한 드라이버는 `KdpStub`/`KdTrap` inline hook으로 커널 디버깅 경로를 수정하므로, 폐기 가능한 VM에서만 사용하세요.<sup>[[1]](#references)</sup>

```text
Host UI / KfConsole
        |
        | TCP 31337 (CMD + debug-event channels)
        v
KfRelay.exe -- DeviceIoControl/IOCTL --> KernelFlirt.sys
        ^
        |
KfLoader.exe -- SCM load/unload/status
```

릴레이는 일반적인 원격 서비스가 아니라 권한이 높은 디버깅 경계입니다. TCP `31337`은 격리된 호스트 전용 네트워크에서만 사용하고, 테스트 서명된 드라이버나 릴레이를 신뢰할 수 없는 네트워크에 절대 노출하지 마세요.<sup>[[1]](#references)</sup>

관련 Windows exploitation 기술:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## 랩 설정 및 첫 중단점

빌드에는 Windows 10/11 x64, C++가 포함된 Visual Studio 2022, WDK 10.0.26100.0 이상, .NET 9가 필요합니다. VM 안에서 드라이버와 릴레이를 로드한 다음 호스트에서 연결하세요. UI에서 원격 EXE 또는 SYS 파일을 열 수 있으며, **Kernel Modules** 뷰에서는 이미 로드된 드라이버에 중단점을 설정할 수 있습니다.<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

랩이 끝나면 `KfLoader.exe unload`를 사용하세요. 콘솔은 연결되지 않은 REPL, 로컬 장치에 대한 직접 액세스, 릴레이 액세스를 지원하며, 아래에 설명된 결정적 `open` 워크플로를 구현하는 것은 릴레이 모드뿐입니다.<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

최소한의 콘솔 워크플로는 다음과 같습니다:<sup>[[2]](#references)</sup>

```text
connect 10.100.102.6:31337
open C:\Temp\target.exe
bp ntdll!NtCreateFile if rcx != 0
g
u rip 8
dq rsp 8
r
detach
```

주소는 표현식입니다. 숫자만 있는 값은 16진수이며, 표현식에는 레지스터, 산술 연산, `[rsp]` 같은 역참조, `ntdll!NtCreateFile` 같은 심볼을 사용할 수 있습니다. 심볼 breakpoint는 `open` 또는 `attach`로 모듈을 열거하고 PDB를 로드한 후에만 추가해야 합니다.<sup>[[2]](#references)</sup>

## `EB FE`를 이용한 결정적 진입점 트래핑

Relay 측 `open`은 대상 프로세스를 일시 중지 상태로 생성하고, 첫 진입점 바이트를 저장한 뒤 `EB FE`를 기록합니다. 그런 다음 진입 스레드를 재개하고 명령어 포인터가 해당 주소에 도달할 때까지 폴링합니다. `EB FE`는 자기 자신으로 되돌아가는 2바이트 short jump이므로, user-mode debug exception 전달에 의존하지 않고 실행을 트래핑합니다. 이어서 relay는 원래 바이트를 복원하고 대상 프로세스를 진입점에서 중지된 상태로 둡니다.<sup>[[2]](#references)</sup>

이 패턴은 일반적인 debugger 설정이 완료되기 전에 초기 loader 경로를 관찰해야 할 때도 유용합니다.<sup>[[2]](#references)</sup>

1. 프로세스를 일시 중지 상태로 생성하고 이미지 매핑 후 실제 진입점을 확인합니다.
2. 원래 진입점 바이트를 저장하고 2바이트 자기 루프로 교체합니다.
3. 진입 스레드를 재개하고 명령어 포인터가 패치된 주소에 도달할 때까지 폴링합니다.
4. 대상 프로세스를 일시 중지하고 분석을 계속하기 전에 원래 바이트를 정확히 복원합니다.

이 기법은 의도적으로 프로세스에 직접 개입합니다. 복원이 이루어지기 전에 debugger 또는 relay가 종료되면 대상 프로세스가 계속 루프를 돌 수 있습니다. KernelFlirt local mode는 relay 측 진입점 패치를 제공하지 않습니다. 대신 프로세스를 직접 시작하고 `attach <pid>`를 사용하세요.<sup>[[2]](#references)</sup>

## breakpoint 방식 선택

KernelFlirt는 부작용이 서로 다른 여러 breakpoint 메커니즘을 제공합니다. 다음 명령을 사용하면 packed code가 스스로를 다시 쓰거나, 실행 페이지가 읽기 전용이거나, software breakpoint 바이트가 무결성 검사를 받는 경우 방식을 바꿀 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

| 방식 | 명령 | 메커니즘 및 용도 |
| --- | --- | --- |
| Software | `bp <expr>` | MDL 기반 `INT3`; RX `.text` 페이지에 계측 가능 |
| 조건부 software | `bp <expr> if <condition>` | 적중할 때마다 평가하고 조건이 false이면 조용히 재개 |
| Hardware execute | `ba e1 <expr>` | 코드 바이트를 변경하지 않고 DR0-DR3 중 하나 사용 |
| Hardware data | `ba w4 <expr>` / `ba r8 <expr>` | 1, 2, 4, 8바이트의 쓰기 또는 읽기/쓰기 감시 |
| Guard page | `bm <expr> [size]` | 메모리 범위 breakpoint에 `PAGE_GUARD` 사용 |
| 임시 | `g <expr>`, `p`, 또는 `o` | 주소까지 실행, step-over, step-out용 helper breakpoint |

`bl`을 사용하면 software, hardware, memory, 임시 항목을 구분할 수 있으며, `bc <address|handle|all>`로 제거할 수 있습니다. Hardware 슬롯은 부족하고 debug-register 상태를 통해 적용되는 반면, guard page는 더 넓은 범위를 다루지만 같은 페이지에 대한 관련 없는 접근에도 트리거됩니다.

## Native x64와 WoW64 stepping

Native x64 single-step은 `IOCTL_KF_SINGLE_STEP`을 통해 processor trap flag를 설정합니다. Step Over는 현재 명령어를 디코딩하고 가능한 다음 주소에 임시 breakpoint를 설정합니다. Step Out은 현재 스택 최상단에서 반환 주소를 읽습니다. 함수 prologue에서는 스택을 전제로 한 이 방식이 맞지 않을 수 있으므로, 확인된 내부 breakpoint를 사용하는 편이 좋습니다.<sup>[[2]](#references)</sup>

`KdTrap` hook은 32비트 exception을 같은 방식으로 포착하지 않습니다. WoW64 대상의 경우 debugger는 Iced로 명령어를 디코딩하고 계산된 다음 `EIP`에 `EB FE`를 기록한 뒤, 스레드의 명령어 포인터를 폴링합니다. 따라서 WoW64에서는 `g <address>`를 사용할 수 없으며, 인수가 없는 `g`는 breakpoint에 도달할 때까지 console을 차단합니다. 먼저 도달 가능한 breakpoint를 설정하고 무기한 실행은 피하세요. `Ctrl+C`를 누르면 폴링이 취소되는 대신 console이 종료됩니다.<sup>[[2]](#references)</sup>

## 메모리, 레지스터 및 심볼을 활용한 분석

console에서는 심볼 기반 중단과 메모리 검사를 결합하고 제어된 패치를 적용할 수 있습니다. 검색 호출은 byte wildcard, ASCII 또는 UTF-16을 지원하며, 검색 범위는 4 MB, 보고되는 일치 항목은 최대 256개로 제한됩니다. 할당 및 보호 명령은 driver의 allocate, free, protect IOCTL에 대응합니다.<sup>[[2]](#references)</sup>

```text
s 7ff700000000 100000 48 8b ?? c3
s 7ff700000000 100000 "MZ"
d rip 40
r rax
r rip=module!Function+5
e rip 90 90
.alloc 1000 rwx
.protect <addr> 1000 rx
.free <addr>
```

PDB 로딩은 각 원격 모듈의 PE 디버그 디렉터리를 읽고, RSDS 식별자를 추출한 다음, DbgHelp/SymSrv를 통해 일치하는 PDB를 찾아 PDB로 로드되었는지 확인합니다. 비공개 PDB는 릴레이 머신에서 대상 옆에 두거나, 호스트의 `_NT_SYMBOL_PATH`에 해당 디렉터리를 추가하세요.<sup>[[2]](#references)</sup>

## 커널 기반 anti-debug 상태 변경

커널 액세스를 사용하면 사용자 모드 디버거로는 안정적으로 숨길 수 없는 지표를 제거할 수 있습니다. 한 번에 하나씩 변경하고 대상 검사를 확인한 뒤, 세션을 끝내기 전에 해당 hook을 되돌리세요.<sup>[[2]](#references)</sup>

```text
!peb
ad clr_debug_port
ad clr_thread_hide
ad ntqsi on
ad spoof on
stats
ad spoof off
ad ntqsi off
```

- `clr_debug_port`는 `EPROCESS.DebugPort`를 지웁니다.
- `clr_thread_hide`는 대상 스레드에서 `HideFromDebugger`를 제거합니다.
- `ntqsi on`은 `NtQuerySystemInformation` 클래스 `0x23`(`SystemKernelDebuggerInformation`)의 결과를 스푸핑합니다.
- `spoof on`은 트랩 메커니즘에 필요한 커널 상태는 유지하면서 사용자 모드에서 `KUSER_SHARED_DATA.KdDebuggerEnabled`를 읽으면 false가 반환되도록 합니다.
- `stats`는 hook 카운터와 기록된 `KiDebugRoutine`, `KdpStub`, `KdTrap` 상태를 확인합니다.

이 작업은 프로세스 및 커널 상태를 변경합니다. 크래시, 오래된 inline hook, 잘못된 구조체 오프셋 또는 완료되지 않은 패치 복원은 VM을 불안정하게 만들 수 있으므로 스냅샷과 격리된 테스트 서명 환경이 필수입니다.<sup>[[1]](#references)</sup>

## References

- [1] [KernelFlirt 저장소 및 주요 문서](https://github.com/AkaTorich/KernelFlirt)
- [2] [KernelFlirt 콘솔 참고 문서](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
