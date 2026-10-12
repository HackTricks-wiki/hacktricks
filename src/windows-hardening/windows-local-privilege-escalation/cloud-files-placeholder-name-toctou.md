# Windows MDL 매핑 사용자 버퍼 Double-Fetch

{{#include ../../banners/hacktricks-training.md}}

Windows 커널 드라이버가 호출자가 제공한 페이지의 데이터를 검증한 뒤, 같은 페이지에 있는 포인터를 보안에 민감한 API에 전달하면 double-fetch가 발생합니다. 페이지를 잠그고 매핑해도 페이지의 내용은 변경 불가능해지지 않습니다. `cldflt.sys`의 CVE-2025-55680은 이 패턴을 보여 줍니다. 드라이버는 Cloud Files placeholder의 상대 경로를 검증한 뒤에도 호출자가 변경할 수 있는 버퍼를 참조한 상태로 객체를 생성했습니다.<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()`는 등록된 Cloud Files sync root 아래에 파일이나 디렉터리를 생성합니다. 취약한 코드 경로에서는 검증 후 이름을 변경해 권한이 높은 생성 작업이 해당 root 밖으로 향하도록 할 수 있었습니다.<sup>[[1]](#references)[[2]](#references)</sup>

## 페이지를 잠가도 데이터가 잠기지 않은 이유

취약한 `HsmpOpCreatePlaceholders()` 코드 경로는 호출자의 payload에 대한 MDL을 할당하고, `ProbeForRead()`와 `MmProbeAndLockPages()`를 호출한 뒤 해당 페이지를 커널 가상 주소 공간에 매핑했습니다. MDL은 물리 페이지를 나타내고 잠가서 상주 상태를 유지합니다. 하지만 바이트를 **스냅샷으로 저장하지는 않습니다**. 따라서 사용자 모드는 드라이버가 시스템 매핑을 통해 읽는 동안에도 같은 물리 메모리를 수정할 수 있습니다.<sup>[[1]](#references)[[3]](#references)</sup>

관련 요청 및 사용 경로는 다음과 같습니다.<sup>[[1]](#references)</sup>

1. `cldapi.dll`은 태그 `IO_REPARSE_TAG_CLOUD` (`0x9000001A`)와 placeholder 생성 작업 `0xC0000001`을 포함한 Cloud Files 제어 코드 `0x903BC`를 전송했습니다.
2. 각 payload 레코드에는 상대 경로와 파일 identity의 16비트 오프셋/길이 쌍이 포함되었습니다. 대부분의 고정 필드는 스택 레코드에 복사했지만, 가변 길이 이름은 매핑된 사용자 페이지에 남아 있었습니다.
3. 드라이버는 UTF-16 이름을 검사해 백슬래시나 콜론이 있으면 거부했습니다.
4. 그런 다음 `Buffer`가 여전히 매핑된 payload를 가리키는 `UNICODE_STRING`을 구성해 `OBJECT_ATTRIBUTES.ObjectName`에 할당했습니다.
5. `FltCreateFileEx2()`가 해당 포인터를 다시 읽었습니다. 따라서 동시에 실행되는 쓰기 작업은 검증 시 읽힌 문자열과 파일 생성 시 읽힌 문자열을 다르게 만들 수 있었습니다.

두 읽기 작업이 모두 커널 가상 주소를 사용하더라도 이는 **double-fetch**입니다. 보안 경계는 드라이버가 어떤 가상 매핑을 역참조하는지가 아니라, 그 매핑의 기반 저장소가 변경 가능한지에 달려 있습니다.<sup>[[1]](#references)</sup>

## Cloud Files 경쟁 상태 구성

공개된 exploit 전략은 반복 요청, 변경 스레드, junction을 사용해 double-fetch를 경로 리디렉션으로 바꿨습니다.<sup>[[1]](#references)</sup>

1. `CfRegisterSyncRoot()`로 공격자가 제어하는 디렉터리를 등록하고, 그 아래에 보호 대상 위치를 가리키는 junction `JUSTASTRING`을 만듭니다.
2. 유효한 단일 구성 요소 이름 `JUSTASTRINGDnewfile.dll`을 담은 공유 placeholder 레코드를 준비합니다.
3. 변경 스레드가 UTF-16 `D` 코드 단위를 `D`와 `\` 사이에서 반복해 전환하도록 합니다. 두 번째 형태는 `JUSTASTRING\newfile.dll`입니다.
4. 동시에 작업자 스레드가 같은 payload를 참조하는 placeholder 생성 요청을 반복 제출하도록 하고, 모니터가 보호 대상 위치를 확인하도록 합니다.
5. 성공한 반복에서는 구분자가 없는 형태가 검증된 뒤, 이후 생성 시 구분자가 포함된 형태가 읽혀 junction을 따라갑니다.

이 primitive로 가능한 것은 보호된 파일이나 디렉터리의 생성뿐입니다. 이를 코드 실행으로 이어 가려면 생성된 파일의 내용을 제어하고, 적합한 DLL side-loading 대상처럼 권한이 높은 소비자가 필요합니다. 원래 분석에서는 이 최종 단계의 chain을 사용했지만, loader, payload 또는 완전한 독립형 exploit은 공개하지 않았습니다.<sup>[[1]](#references)</sup>

Windows 경로 조회 경쟁 상태를 의도적으로 확대하는 상호 보완적인 기법은 [Kernel Race Condition Exploitation via Object Manager Slow Paths](kernel-race-condition-object-manager-slowdown.md)를 참조하세요.

## References

- [1] [Exodus Intelligence - Microsoft Windows Cloud Files Minifilter TOCTOU 권한 상승](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - CfCreatePlaceholders 함수](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - MmProbeAndLockPages 함수](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}
