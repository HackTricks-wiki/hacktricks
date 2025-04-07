# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## 어떻게 작동하는가

프로세스는 아래 단계에 설명되어 있으며, SMB를 통해 대상 머신에서 원격 실행을 달성하기 위해 서비스 바이너리가 어떻게 조작되는지를 보여줍니다:

1. **ADMIN$ 공유에 서비스 바이너리를 SMB를 통해 복사**합니다.
2. **원격 머신에 서비스 생성**이 바이너리를 가리키도록 수행됩니다.
3. 서비스가 **원격으로 시작**됩니다.
4. 종료 시, 서비스는 **중지되고 바이너리는 삭제**됩니다.

### **PsExec 수동 실행 프로세스**

msfvenom으로 생성되고 Veil을 사용하여 안티바이러스 탐지를 피하기 위해 난독화된 실행 가능한 페이로드가 있다고 가정합니다. 이 페이로드는 'met8888.exe'라는 이름을 가지며, meterpreter reverse_http 페이로드를 나타냅니다. 다음 단계가 수행됩니다:

- **바이너리 복사**: 실행 파일은 명령 프롬프트에서 ADMIN$ 공유로 복사되지만, 파일 시스템의 어디에나 배치하여 숨길 수 있습니다.
- 바이너리를 복사하는 대신 `powershell.exe` 또는 `cmd.exe`와 같은 LOLBAS 바이너리를 사용하여 인수에서 직접 명령을 실행할 수도 있습니다. 예: `sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"`
- **서비스 생성**: Windows `sc` 명령을 사용하여 원격으로 Windows 서비스를 쿼리, 생성 및 삭제할 수 있으며, 업로드된 바이너리를 가리키는 "meterpreter"라는 이름의 서비스가 생성됩니다.
- **서비스 시작**: 마지막 단계는 서비스를 시작하는 것으로, 바이너리가 진정한 서비스 바이너리가 아니기 때문에 예상 응답 코드를 반환하지 않아 "time-out" 오류가 발생할 가능성이 높습니다. 이 오류는 바이너리 실행이 주요 목표이므로 중요하지 않습니다.

Metasploit 리스너를 관찰하면 세션이 성공적으로 시작되었음을 알 수 있습니다.

[sc 명령에 대해 더 알아보기](https://technet.microsoft.com/en-us/library/bb490995.aspx).

자세한 단계는 다음에서 확인하세요: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

- **Windows Sysinternals 바이너리 PsExec.exe**를 사용할 수도 있습니다:

![](<../../images/image (928).png>)

또는 webddav를 통해 접근할 수 있습니다:
```bash
\\live.sysinternals.com\tools\PsExec64.exe -accepteula
```
- 당신은 또한 [**SharpLateral**](https://github.com/mertdas/SharpLateral)를 사용할 수 있습니다:
```bash
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- 또한 [**SharpMove**](https://github.com/0xthirteen/SharpMove)를 사용할 수 있습니다:
```bash
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- **Impacket의 `psexec` 및 `smbexec.py`**를 사용할 수도 있습니다.


{{#include ../../banners/hacktricks-training.md}}
