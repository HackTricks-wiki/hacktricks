# Kernel-Mode File Access Check 우회

{{#include ../../banners/hacktricks-training.md}}

## 취약한 드라이버 패턴

드라이버는 호출자를 가장하는 것만으로 호출자의 보안 경계를 유지할 수 없습니다. 커널 모드에서 객체를 열면 일반적으로 액세스 검사가 우회됩니다. `OBJ_KERNEL_HANDLE`은 결과 핸들을 커널 모드에서만 사용할 수 있게 할 뿐입니다. 드라이버가 사용자 모드를 대신해 객체를 열거나 조작할 때는 `OBJ_FORCE_ACCESS_CHECK`도 사용해야 Object Manager가 유효 토큰에 대해 요청된 액세스를 검사합니다.<sup>[[3]](#references)[[4]](#references)</sup>

파일 처리 IOCTL과 create callback에서 다음 흐름을 감사하세요:<sup>[[3]](#references)[[4]](#references)</sup>

1. 사용자 모드에서 경로, 소스 핸들, 원하는 액세스 권한 또는 작업 유형을 제공합니다.
2. 드라이버가 호출자를 가장하지만, `OBJ_FORCE_ACCESS_CHECK` 없이 `IoCreateFileEx`, `ZwCreateFile` 또는 유사한 루틴을 호출합니다.
3. 커널 전용 파일 또는 디렉터리 핸들이 핸들별 상태에 저장됩니다.
4. 이후 작업에서 첫 번째 열기 시 요청된 액세스 마스크처럼 공격자가 영향을 줄 수 있는 상태를 바탕으로 가장 여부를 결정합니다.
5. 권한 있는 분기에서 `BypassAccessCheck` 정보 클래스를 사용해 이름 변경 또는 링크 작업을 수행합니다.

이것은 반드시 메모리 손상이 동반되는 것은 아닌 **confused-deputy 파일 프리미티브**입니다. 특히 위험한 상태 역전은 “쓰기 요청 시 가장하고, 쓰기 요청이 없으면 권한을 유지한다”는 동작입니다. 이런 설계에서는 의도적으로 읽기 권한만 요청하면 더 강력한 경로를 열 수 있습니다.<sup>[[3]](#references)</sup>

## vSMB 예시: 권한 있는 루트와 권한 있는 이름 변경

`storvsp.sys`는 Virtual Server Message Block (vSMB)를 구현합니다. **Virtual Machine Platform** 기능이 활성화되면 사용자 모드에서 `\\.\STORVSP`를 통해 `\Device\STORVSP`에 접근할 수 있습니다. vSMB 파일 시스템 경로는 `\\.\STORVSP\VSMB\??\C:\path` 형식입니다. CVE-2025-59517과 CVE-2025-64673은 일관되지 않은 두 가지 액세스 제어 결정으로 이 인터페이스가 로컬 권한 상승에 악용될 수 있음을 보여주었습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

소스 코드의 함수와 CVE 간 매핑은 Microsoft 소스가 아니라 패치된 바이너리의 리버스 엔지니어링을 바탕으로 합니다. 연구진은 두 식별자가 서로 반대 함수에 해당할 수도 있다고 경고합니다.<sup>[[3]](#references)</sup>

### 1. 보호된 디렉터리를 루트로 하는 읽기 전용 공유 만들기

취약한 create 경로는 요청된 권한을 `HasReadAccess`, `HasWriteAccess`, `HasAppendAccess`와 같은 지속 상태 플래그에 기록했습니다. 그런 다음 `OBJ_KERNEL_HANDLE`은 사용했지만 `OBJ_FORCE_ACCESS_CHECK`는 사용하지 않고 백업 경로를 열었습니다. 따라서 가장을 시도해도 파일 열기 시 호출자의 NTFS 권한이 적용되지 않았습니다.<sup>[[3]](#references)[[4]](#references)</sup>

`FILE_READ_DATA`만 요청하세요. 이렇게 하면 `HasWriteAccess`는 설정되지 않은 상태로 유지되지만, 내부 루트가 보호된 디렉터리인 공유를 만들 수 있습니다:<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

중요한 객체는 user-mode System32 디렉터리 핸들이 아닙니다. 권한이 높은 kernel root handle을 포함하는 driver state와 연결된 vSMB device handle입니다.<sup>[[3]](#references)</sup>

### 2. 상태 불일치를 이용해 보호된 파일 교체

IOCTL `0x240330`은 source file handle, information class, 가변 길이 information buffer를 받았습니다:<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

취약한 핸들러는 `FileRenameInformation`, `FileLinkInformation`, `FileRenameInformationEx`를 허용했습니다. 일반적인 rename 경로에서는 부모 경로와 마지막 구성 요소를 분리한 다음, 저장된 루트 핸들을 기준으로 부모를 열었습니다. 이때도 `OBJ_FORCE_ACCESS_CHECK` 없이 `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE`를 사용했습니다. rename 구조체에 공격자가 제공한 `RootDirectory`가 0이 아니면 거부했으므로, 드라이버가 자체적으로 권한이 있는 디렉터리 핸들을 제공했습니다.<sup>[[3]](#references)</sup>

악용 가능한 분기는 stage 1에서 write access를 **요청하지 않을 때** 선택되었습니다.<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: 저장된 루트 보안 컨텍스트로 impersonate합니다.
- `HasWriteAccess == 0`: impersonation을 건너뛰고 `FileRenameInformation` 또는 `FileRenameInformationEx`를 해당 `BypassAccessCheck` variant로 변환합니다.

핸들러는 공격자가 제공한 원본 핸들을 `PsInitialSystemProcess`로 복제하고, 이를 file object로 참조한 뒤, rename 구조체에 권한이 있는 대상 디렉터리 핸들을 설정하고 `ZwSetInformationFile`을 호출했습니다. `ReplaceIfExists = TRUE`인 경우, 따라서 호출자가 제어하는 파일로 보호된 루트 아래의 기존 파일을 대체할 수 있었습니다.<sup>[[3]](#references)</sup>

유사한 핸들러를 검토할 때는 모든 분기에서 **핸들의 출처와 보안 컨텍스트를 모두** 추적하세요. 입력 검증, 정수 오버플로 검사, `IO_STOP_ON_SYMLINK` 사용, 허용하는 정보 클래스 제한만으로는 권한이 있는 루트 핸들과 access-check-bypass 연산의 조합을 상쇄할 수 없습니다.<sup>[[3]](#references)</sup>

## 보호된 파일 쓰기에서 SYSTEM 실행까지

권한이 있는 프로세스가 교체된 모듈을 나중에 로드하면, 보호된 파일 교체 primitive가 code execution으로 이어집니다. 시연된 체인에서는 대상이 `C:\Windows\System32\wuapi.dll`이었습니다. 로컬 서버 COM 클래스 `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}`를 인터페이스 `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}`에 대해 활성화하고 `IWaaSRemediation::LaunchDetectionOnly()`를 호출하면 SYSTEM 프로세스가 해당 DLL을 로드했습니다.<sup>[[3]](#references)</sup>

이 COM 호출은 **activation trigger**이지 [COM registry hijacking](com-hijacking.md)이 아닙니다. 파일 primitive가 심어 둔 모듈을 제공하고, 권한이 있는 loader가 이를 실행합니다. 다른 protected-write 체인의 경우 대상을 선택하기 전에 정확한 이미지, DLL 경로, 서명 정책, bitness, export 함수, 신뢰할 수 있는 trigger를 파악하세요. 일반적인 loader 분석 절차는 [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack)을 참고하세요.<sup>[[3]](#references)</sup>

### Session 0 token을 대화형 desktop으로 이동

서비스가 로드한 payload는 일반적으로 Session 0에서 실행됩니다. 대화형 프로세스를 만들려면 `WTSGetActiveConsoleSessionId`로 활성 콘솔 세션을 가져오고, 필요한 token privileges를 활성화한 다음, 현재 SYSTEM token을 primary token으로 복제하고 `TokenSessionId`를 활성 세션으로 설정할 수 있습니다. 그런 다음 `CreateProcessAsUserW`에서 해당 token과 `STARTUPINFO.lpDesktop = L"winsta0\\default"`를 사용합니다.<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege`는 이 시나리오에서 토큰의 세션 ID를 설정하는 데 필요합니다. 대화형 윈도우 스테이션과 데스크톱도 토큰에 대한 액세스를 허용해야 합니다. 더 넓은 토큰 복사 워크플로는 [Session 0에서 토큰 복제](sedebug-+-seimpersonate-copy-token.md)를 참조하세요.<sup>[[3]](#references)[[5]](#references)</sup>

## 패치 및 검토 지침

Microsoft의 2025년 12월 업데이트로 시연된 체인이 수정되었습니다. 리버스 엔지니어링 결과, 패치된 vSMB 생성 경로는 `FILE_WRITE_DATA` 없이 공유 루트를 요청하는 신뢰할 수 없는 호출자를 거부하는 것으로 확인되었습니다. 관련 작업에도 강제 액세스 검사가 추가되었습니다. 이로써 권한이 없는 호출자가 권한 있는 루트를 얻기 전에 상태 반전을 차단합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

드라이버 코드는 다음 규칙을 적용하세요.<sup>[[3]](#references)[[4]](#references)</sup>

- 사용자 모드 요청을 대신해 객체를 열 때마다 `OBJ_FORCE_ACCESS_CHECK`를 추가하세요. `OBJ_KERNEL_HANDLE`을 권한 제어 수단으로 취급하지 마세요.<sup>[[4]](#references)</sup>
- 요청자 모드와 유효한 주체 컨텍스트를 캡처하고 검증하세요. 요청된 권한에 따라 더 높은 권한으로 실행되는 분기를 선택하지 못하게 하세요.
- 올바른 객체 유형, 액세스 마스크, `UserMode`를 사용해 사용자 핸들을 검증하세요. 핸들을 시스템 프로세스로 복제해도 요청된 작업의 권한은 검증되지 않습니다.
- 대상 확인은 신뢰할 수 있는 핸들을 기준으로 수행하되, 그 신뢰할 수 있는 핸들 자체가 요청자에 대한 강제 액세스 검사 아래에서 열렸는지 확인하세요.
- 사용자가 구동하는 작업에는 `File*BypassAccessCheck` 클래스를 사용하지 마세요. 내부 코드에서 꼭 필요한 경우, 사용자가 제어하는 액세스 플래그와 독립적인 권한 결정으로 해당 경로를 제한하세요.
- 영향을 받는 시스템에 패치를 적용하세요. Virtual Machine Platform이 `storvsp.sys`를 로드할 때 취약점이 발생할 수 있습니다.<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - 가상 공유에서 실제 셸로: Windows의 일관성 없는 액세스 제어를 활용한 LPE](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - 객체 핸들](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - CreateProcessAsUserW 함수](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}
