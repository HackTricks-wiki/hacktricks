# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## 작동 방식

Service Control Manager Remote Protocol (SCMR)은 원격 컴퓨터의 Windows services를 구성하고 제어하기 위한 RPC 기반 protocol입니다. 충분한 permissions가 있으면 operator는 binary path에 command가 포함된 service를 생성하거나 재구성한 다음 해당 service를 시작하여 원격으로 command를 실행할 수 있습니다.<sup>[[1]](#references)</sup>

service account가 지정되지 않으면 `CreateService`는 광범위한 로컬 privileges를 가진 `LocalSystem`을 사용합니다. 이것이 성공적인 SCM execution의 영향이 큰 이유입니다. 이 방식이 본질적으로 UAC 또는 Microsoft Defender를 disable하는 것은 아닙니다. caller에게는 여전히 remote SCM rights가 필요하며 endpoint controls는 service 또는 payload를 검사하거나 차단할 수 있습니다.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Tools

**SharpMove**는 SCM 및 기타 여러 Windows mechanisms를 통한 authenticated remote execution을 지원합니다. 다음 예제에서는 SCM action을 선택하고 `WindowsDebug`라는 service를 생성한 뒤, remote host에 이미 존재하는 payload를 해당 service가 가리키도록 설정합니다.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Service Control Manager Remote Protocol 개요](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - LocalSystem 계정](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - `CreateService` 함수](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
