# Windows 커널 루트킷과 DKOM

{{#include ../../banners/hacktricks-training.md}}

## 범위

침해 후 implant는 서명된 커널 드라이버를 서비스로 로드하고 `IRP_MJ_DEVICE_CONTROL`을 통해 사용자 모드 제어 인터페이스를 노출할 수 있습니다. 드라이버 서명은 Windows가 해당 이미지를 허용한다는 사실만 확인할 뿐, IOCTL 권한 부여, 메모리 작업, 콜백 또는 후크가 안전하다는 뜻은 아닙니다. 분석된 루트킷 하나는 정상 작동 중 세 개의 핸들러를 사용했지만, post-exploitation을 위한 추가 프리미티브를 수십 개 노출했습니다. 따라서 리버스 엔지니어링은 악성코드 추적에서 관찰된 요청만이 아니라 전체 디스패처를 대상으로 해야 합니다.<sup>[[1]](#references)</sup>

## 서명된 드라이버 및 IOCTL 트리아지

`DriverEntry`에서 시작해 디바이스 객체와 DOS 심볼릭 링크를 기록하고, `MajorFunction[IRP_MJ_DEVICE_CONTROL]` 루틴을 찾은 다음 핸들러로 이어지는 모든 비교 및 테이블 항목을 매핑합니다. 사용자 모드에서 여는 이름과 드라이버가 실제로 생성하는 이름을 대조합니다. 관찰된 한 체인에서는 `\\.\msagent`를 열었지만, 드라이버는 `\Device\ToolTool`과 `\DosDevices\ToolTool`을 생성했습니다. 이러한 불일치는 다른 샘플/설정, 누락된 설정 로직 또는 분석상의 불일치를 나타낼 수 있습니다.<sup>[[1]](#references)</sup>

각 제어 코드를 디코딩한 뒤 입력 구조를 재구성합니다.<sup>[[1]](#references)</sup>

```python
def decode_ioctl(code):
    return {
        "device_type": code >> 16,
        "access": (code >> 14) & 3,
        "function": (code >> 2) & 0xfff,
        "method": code & 3,
    }

for code in (0x2220F0, 0x222120, 0x2221E0):
    print(hex(code), decode_ioctl(code))
```

이 세 코드는 `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS`, `METHOD_BUFFERED`로 디코딩됩니다. 그렇다고 권한이 없는 호출자가 해당 코드에 접근할 수 있다는 뜻은 아닙니다. 장치 DACL, create/open 디스패치, 요청별 호출자 검사, 예상 버퍼 길이, 내장 포인터, PID 수명 처리, 그리고 핸들러가 호출자가 제공한 PID나 플래그를 신뢰하는지 여부도 확인해야 합니다.<sup>[[1]](#references)</sup>

implant가 명령의 일부만 사용하더라도, 나머지 핸들러를 죽은 코드라고 치부하지 말고 primitive별로 분류하세요. 단일 다기능 드라이버가 다음과 같은 모든 유형의 기능을 노출한 사례가 있습니다.<sup>[[1]](#references)</sup>

- **제어/구성:** rootkit 상태 전환, 보호 대상 경로·프로세스·C2 주소 추가, 제거, 조회 또는 초기화.
- **프로세스 조작:** PID 종료, 이미지 매핑 해제, `NtCreateThreadEx`를 이용한 inject, 프로세스 또는 사용자 모듈 숨김/복원, PPL 보호 제거.
- **커널 조작:** 로드된 드라이버 unlink, 알림 콜백 열거/비활성화/복원, 다른 드라이버 수동 매핑, 임의 커널 주소에 쓰기.
- **객체 조작:** 파일 삭제/복호화 및 레지스트리 값 생성 또는 수정.

## 취약한 서명 드라이버를 통한 수동 커널 매핑

커널 메모리 읽기/쓰기 작업을 지원하는 서명된 드라이버는 서명되지 않은 드라이버 이미지를 일반 드라이버처럼 Windows에 로드하도록 요청하지 않고도 로더 역할을 할 수 있습니다.<sup>[[2]](#references)[[7]](#references)</sup> LocalStranger 예제는 기존 `\\.\WinNotify` 장치를 엽니다. 해당 소스만으로는 임의의 호스트에서 권한이 없는 사용자가 드라이버를 설치, 시작 또는 열 수 있음을 입증하지 않습니다.<sup>[[2]](#references)[[3]](#references)</sup> mapper는 이미지 경로를 받아 로드된 커널의 베이스를 조회하고, 장치의 가상 메모리 읽기/쓰기 IOCTL을 사용합니다.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

읽기/쓰기 접근을 커널 호출로 전환하기 위해, mapper는 `MmGetVirtualForPhysical`의 PTE-base immediate를 읽고 `NtAddAtom`을 포함하는 페이징 엔트리를 순회합니다.<sup>[[5]](#references)[[7]](#references)</sup> PTE 계산식은 `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)`이며, 코드는 large-page PDE도 확인합니다.<sup>[[5]](#references)[[7]](#references)</sup> mapper는 해당 엔트리를 일시적으로 쓰기 가능하게 만들고, 시스템 호출 엔트리를 원하는 커널 함수로 점프하는 코드로 바꾼 뒤, 사용자 모드 `NtAddAtom` stub을 호출하고 원래 바이트와 페이지 엔트리를 모두 복원합니다.<sup>[[6]](#references)</sup>

mapper는 이 호출 경로로 `ExAllocatePool`을 호출하고, PE 섹션과 import, relocation을 이미지에 매핑한 뒤, 할당된 메모리에 기록하고 진입점을 호출합니다.<sup>[[7]](#references)[[8]](#references)</sup> 이 구현은 x64 relocatable PE 이미지만 지원하며, PTE-base를 읽을 때 `MmGetVirtualForPhysical + 34`라는 고정 레이아웃도 가정합니다.<sup>[[5]](#references)[[8]](#references)</sup> 따라서 이를 독립적인 KASLR 우회나 HVCI 또는 PatchGuard가 해당 매핑을 허용한다는 증거가 아니라, 빌드에 따라 달라지는 기법으로 취급하세요.<sup>[[5]](#references)[[8]](#references)</sup> 커널 R/W를 데이터 전용으로 사용하는 방법은 [SYSTEM token theft](arbitrary-kernel-rw-token-theft.md)를 참조하세요.

## 신뢰 프로세스 예외 처리

유용한 설계 패턴은 PID와 **신뢰됨** 플래그를 등록하는 IOCTL입니다. 그런 다음 동일한 신뢰 확인 로직을 파일, 레지스트리, 프로세스 및 스레드 필터에서 참조합니다. 신뢰되지 않은 도구에는 필터링된 열거 결과, 축소된 핸들 권한 또는 `STATUS_ACCESS_DENIED`를 반환하고, implant는 자체 숨겨진 객체를 계속 갱신할 수 있습니다. 이를 권한 부여 경계로 보고, 항목의 인증 및 동기화 방식과 프로세스 종료 또는 PID 재사용 후 항목이 제거되는지 확인하세요.<sup>[[1]](#references)</sup>

Rootkit은 `REG_MULTI_SZ` 값에 정책을 유지하고, 파일·디렉터리·레지스트리 키·레지스트리 값·무시할 이미지·보호할 이미지·숨길 이미지 목록을 AVL tree로 컴파일할 수 있습니다. 분석할 때는 이러한 공유 tree를 읽고 쓰는 모든 코드를 추적하세요. 함수 이름이 제거되어 있더라도 이 tree를 통해 레지스트리 구성, IOCTL, 콜백 및 필터링 로직을 연결할 수 있습니다.<sup>[[1]](#references)</sup>

## DKOM을 이용한 프로세스 및 모듈 숨김

### `EPROCESS.ActiveProcessLinks`

`ActiveProcessLinks` 오프셋은 Windows 빌드에 따라 다릅니다. 버전 변화에 대응하는 rootkit은 알려진 후보를 확인한 뒤, 이웃 항목이 후보 항목을 다시 가리키는 일관된 `LIST_ENTRY`를 `EPROCESS`에서 검색할 수 있습니다. 발견한 오프셋을 저장하고, 이웃 항목의 `Flink`/`Blink`를 다시 연결해 프로세스를 숨긴 다음, 나중에 항목을 다시 연결할 수 있도록 상태를 보존합니다. 프로세스는 계속 실행되지만 활성 프로세스 목록을 순회하는 열거 도구에는 나타나지 않습니다.<sup>[[1]](#references)</sup>

이는 종료가 아니라 **DKOM**입니다. 탐지하려면 목록 기반 결과를 pool/object scan, 스레드 소유 관계, 핸들 테이블, 스케줄러 흔적, 커널 메모리 검사 등 독립적인 증거와 비교해야 합니다. scan에는 보이지만 기준 목록에는 없는 프로세스는 어느 한쪽의 결과만으로 판단하는 것보다 의미가 큽니다.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

이에 해당하는 모듈 숨김 primitive는 `PsLoadedModuleList`에서 대상 항목을 찾아 인접한 `Flink`/`Blink` 포인터를 수정합니다. 드라이버는 계속 매핑된 상태로 실행되지만, 목록에 기반한 모듈 조회에서는 빠집니다. 로더 목록을 실행 가능한 커널 매핑, pool tag, 장치/드라이버 객체, 서비스 키, 콜백 주소 및 목록에 없는 이미지 영역을 가리키는 디스패치 포인터와 비교하세요.<sup>[[1]](#references)</sup>

## 콜백 기반 보호 및 은폐

Rootkit은 문서화된 콜백 프레임워크에 DKOM 및 hook을 결합할 수 있습니다.<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks`의 `PsProcessType` 및 `PsThreadType`에 대한 사전 작업 핸들러는 신뢰되지 않은 호출자가 보호 대상에 대한 핸들을 열 때 종료, VM 접근, 핸들 복제 또는 스레드 조작에 사용되는 권한을 제거합니다. 콜백 altitude를 기록하고 각 콜백 주소가 속한 모듈을 확인하세요.
- `PsSetCreateProcessNotifyRoutineEx` 및 `PsSetLoadImageNotifyRoutine`은 프로세스와 이미지가 나타날 때 보호/무시/숨김 상태를 유지합니다. 등록 전에 존재하던 객체는 한 번의 프로세스 순회로 보완할 수 있습니다.
- 파일 시스템 minifilter는 구성된 경로에 대한 접근을 거부합니다. 특이한 구현은 `Instances` 키를 만들고, altitude를 동적으로 선택한 뒤, `FltRegisterFilter`가 충돌을 보고하면 값을 증가시켜 재시도할 수 있습니다.
- `CmRegisterCallbackEx` 루틴은 열거 결과에서 보호된 이름을 숨기고 직접 열기, 이름 변경, 설정 또는 삭제 작업을 거부하면서 등록된 신뢰 프로세스는 예외 처리할 수 있습니다.

`ObRegisterCallbacks` 등록, 레지스트리 콜백 altitude, `fltmc filters` 출력, 서비스 `Instances` 키 및 콜백 주소를 서로 연관 지어 확인하세요. 정상 도구의 결과가 필터링되고 있다면 오프라인 메모리 이미지나 다른 신뢰할 수 있는 수집 계층에서 해당 구조를 검사하세요.<sup>[[1]](#references)</sup>

## Nsiproxy 결과 필터링

네트워크 은폐는 `\Driver\Nsiproxy`를 대상으로 할 수 있습니다. `ObReferenceObjectByName`으로 드라이버 객체를 가져와 핸들러 포인터를 저장하고, 이를 wrapper로 바꾼 다음, 사용자 모드에 전달하기 전에 IOCTL로 관리되는 C2 목록과 일치하는 반환된 IPv4 레코드를 제거합니다. 필터링된 NSI 데이터를 사용하는 애플리케이션에서는 트래픽이 실제로 존재하더라도 해당 연결이 표시되지 않을 수 있습니다.<sup>[[1]](#references)</sup>

호스트의 연결 정보를 패킷 캡처, WFP/ETW 원격 측정 데이터 및 커널 메모리의 네트워크 객체와 비교하세요. 또한 `Nsiproxy` 디스패치/핸들러 포인터를 검사하고 각 포인터가 예상된 서명 모듈 내부를 가리키는지 확인하세요. 목록에 없는 매핑을 가리키는 포인터는 네트워크 필터링을 `PsLoadedModuleList` DKOM과 연결할 수 있습니다.<sup>[[1]](#references)</sup>

## 조사 체크리스트

가장 강력한 신호는 특정 파일명이나 hash가 아니라 계층 간 불일치입니다. 다음 항목을 상호 연관 지어 확인하세요.<sup>[[1]](#references)</sup>

1. 커널 서비스 생성 기록과, 인증서 발급 시기·게시자·경로가 설치된 제품과 일치하지 않는 서명 드라이버.
2. 장치 생성, DOS link 및 IOCTL 트래픽. 여기에는 사용자 모드와 커널의 장치 이름 불일치도 포함됩니다.
3. PID 등록 요청 이후 다른 프로세스에서 동일 객체를 열거, 수정 또는 삭제하려 할 때 발생하는 실패.
4. 주소가 일반적으로 열거된 드라이버에 속하지 않는 객체/레지스트리/프로세스/이미지 콜백, minifilter 인스턴스 및 hook.
5. 목록 기반 및 scan 기반 프로세스, 모듈, 콜백, 네트워크 인벤토리 간의 차이.

## References

- [1] [Kaspersky Securelist - HoneyMyte, 서명된 Windows 커널 rootkit으로 CoolClient 강화](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [LocalStranger README](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [LocalStranger 드라이버 초기화](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [LocalStranger mapper 명령줄](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [LocalStranger 커널 export 및 PTE-base 확인](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [LocalStranger 커널 호출 trampoline](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [LocalStranger mapper 메모리 할당 및 진입점 호출](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [LocalStranger PE 매핑](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [LocalStranger 커널 및 시스템 호출 컨텍스트](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [LocalStranger 가상 메모리 IOCTL wrapper](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
